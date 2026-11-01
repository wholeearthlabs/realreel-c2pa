# @realreel/photo-attest

[![npm](https://img.shields.io/npm/v/@realreel/photo-attest)](https://www.npmjs.com/package/@realreel/photo-attest)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue)](https://github.com/wholeearthlabs/realreel-c2pa/blob/main/LICENSE)
![iOS 16+](https://img.shields.io/badge/iOS-16%2B-lightgrey)
![Android API 28+](https://img.shields.io/badge/Android-API%2028%2B-lightgrey)

Expo native module for **hardware-bound C2PA capture signing** — the client half
of the [RealReel C2PA stack](https://github.com/wholeearthlabs/realreel-c2pa). It
mints a per-device signing key in secure hardware, attests the device to a
platform root, and signs captures so the
[verifier](https://github.com/wholeearthlabs/realreel-c2pa/tree/main/verifier)
can prove a photo or video came from a genuine, untampered device.

|                    | iOS                                   | Android                                              |
| ------------------ | ------------------------------------- | ---------------------------------------------------- |
| **Signing key**    | ECDSA P-256 in the Secure Enclave     | ECDSA P-256 in AndroidKeyStore (StrongBox, else TEE) |
| **Enrollment**     | App Attest (`DCAppAttestService`)     | Key Attestation certificate chain                    |
| **Every upload**   | Fresh App Attest assertion (Stage 2)  | Fresh Play Integrity token (Stage 2)                 |

Stage 1 (capture) carries no attestation envelope: device trust comes from
enrollment, and the per-upload envelope binds each upload to a fresh single-use
server challenge.

> [!IMPORTANT]
> **Reference implementation, best-effort support.** Published so the RealReel
> signing path is auditable and reusable, not as a turnkey dependency. The native
> Swift / Kotlin compiles only inside a full Expo + Xcode / Gradle app, and has
> hard build prerequisites (below). Expect to adapt it.

## Install

```bash
npx expo install @realreel/photo-attest
```

Autolinked — no manual native linking — but the build fails without the
configuration below.

## Required configuration

```js
// app.config.js / app.json
export default {
  plugins: [
    // Wires the iOS Swift Package deps (c2pa-swift `C2PA` + swift-certificates
    // `X509`) into the Podfile on every prebuild.
    "@realreel/photo-attest",

    [
      "expo-build-properties",
      {
        ios: { deploymentTarget: "16.0" },
        android: {
          minSdkVersion: 28,
          extraMavenRepos: ["https://www.jitpack.io"],
          packagingOptions: { exclude: ["/META-INF/LICENSE.md"] },
        },
      },
    ],
  ],
};
```

Then regenerate the native projects: `npx expo prebuild --clean`.

Why each setting (kept explicit so your app stays in control of its min versions
and repositories):

- **iOS deployment target 16.0** — `c2pa-swift`'s floor.
- **Android `minSdkVersion` 28** — `c2pa-android`'s floor. Its AAR also needs
  `compileSdk` 36 (Expo SDK 57's default).
- **JitPack** — `c2pa-android` (`com.github.contentauth:c2pa-android`) is
  distributed there.
- **Exclude `/META-INF/LICENSE.md`** — BouncyCastle 1.85+ ships one in each of
  bcprov, bcpkix and bcutil, and AGP doesn't drop the duplicate.

The config plugin does only what has no other path: it attaches the two Swift
Packages to the **PhotoAttest pod target** alone, since attaching them to the
app target too causes a duplicate-symbol explosion. See `plugin/src/index.ts`
and `ios/PhotoAttest.podspec`.

## API

Fully typed in `build/index.d.ts`. The web entry point is a stub that throws.

| Group              | Methods                                                                                           |
| ------------------ | ------------------------------------------------------------------------------------------------- |
| Capability         | `isHardwareSupported()`, `isAppAttestAvailable()`                                                 |
| Keys + enrollment  | `generateAndAttestKey()`, `generateKey()`, `getAttestation()` (iOS), `generateCSR()`, `getPublicKey()`, `hasKey()`, `deleteKey()` |
| Upload attestation | `generateCaptureAttestation()` (iOS App Attest), `generatePlayIntegrityToken()` (Android)          |
| Signing            | `signC2PACapture()`, `signC2PAUpload()`, `signTimestampUpdateManifest()`                           |
| Media library      | `overwriteMediaLibraryAsset()`                                                                     |

These are methods on `PhotoAttest` (the default export, also named);
`normalizeMediaPath` is a separate named export.

### Trust anchors at ingest

`signC2PAUpload()` and `signTimestampUpdateManifest()` take `trustAnchorsPem`, a
concatenated PEM pool (CA + TSA roots) that c2pa-rs validates the parent
ingredient against, recording the outcome in the signed `c2pa.ingredient.v3`
`validationResults` — C2PA generator conformance requires consulting the CA and
TSA Trust Lists at ingest. Pass `CLIENT_TRUST_ANCHORS_PEM` from
`@realreel/c2pa-trust-core/trust-anchors`. Trust failures, and a pool the native
build can't load, are recorded or degraded, never thrown; see the option's JSDoc.

### File paths

Every path argument accepts a plain absolute path **or** a local `file://` URI,
so an Expo `MediaLibrary` / `ImagePicker` / `Camera` / `FileSystem` uri passes
straight through:

```ts
// file:///storage/emulated/0/Download/Quick%20Share/capture.jpg
const parent = await new MediaLibrary.Asset(id).getUri();

await PhotoAttest.signC2PAUpload(alias, transformedPath, {
  parentMediaPath: parent,
  certChainPEM,
  actions,
});
```

Don't hand-strip the scheme. Both platforms percent-encode these URIs, so
`uri.replace('file://', '')` leaves a `%20` wherever the path has a space, and
the file is then quietly not found. The bridge converts for you (and exports
`normalizeMediaPath` if you need it directly); a plain path passes through
untouched.

## Updating the C2PA version

`ios/C2PA.version` pins `c2pa-swift` (formerly `c2pa-ios`) — the config plugin
reads it at prebuild — and `android/build.gradle` pins `c2pa-android`. Keep the
two in lockstep.

- The plugin's exact swift-certificates pin (`SWIFT_CERT_VERSION`) must satisfy
  the new c2pa-swift's `Package.swift` floor, or SPM resolution fails.
- An existing `ios/` keeps the old injected Podfile snippet — regenerate with
  `npx expo prebuild --clean`.
- Check which c2pa-rs each release embeds before bumping: c2pa-swift's
  `Configurations/Base.xcconfig` (`C2PA_VERSION`) and c2pa-android's
  `library/gradle.properties` (`c2paVersion`).

### Migrating to c2pa-rs 0.92 (required before any bump past 0.91)

c2pa-rs 0.92 (scheduled mid-November 2026) removes two things this module still
uses, and neither removal fails loudly. Do both, in lockstep, on the bump that
crosses 0.92.

#### Trust anchors → `trust.anchors[]`

`settingsWithTrustAnchors` (both platforms) writes the trust pool as the
deprecated `trust.trust_anchors`. 0.92 removes that field, and **unknown settings
keys are ignored** — so bumping without this migration signs anchorless with no
error, and every recorded parent validation reads `untrusted`.

It isn't migrated yet because on 0.91 the legacy field is the only form parsed at
settings load (`merge_legacy_trust_anchors` in c2pa-rs `sdk/src/settings/mod.rs`),
so a pool the engine can't read throws into the anchorless-with-a-log fallback;
`trust.anchors[]` entries are merged in unchecked and would fail later, past it.

When a c2pa-swift / c2pa-android release moves to c2pa-rs ≥ 0.92:

1. Confirm the new engine parses `trust.anchors[]` at load (`with_string` /
   `from_string` → the anchors get `test_load_trust` / `validate()`). If it
   doesn't, keep the bad-pool fallback honest another way first, e.g. parse the
   pool natively.
2. Switch both platforms, in lockstep, to the shape 0.91 derives from the legacy
   field:

   ```json
   "trust": { "trust_config": "<EKU list>", "anchors": [ { "trust_kind": "manifest", "trust_uri": "system_anchors", "trust_anchors": "<PEM pool>" } ] }
   ```

   - Keep `trust_config` (`TRUST_SETTINGS_JSON`, also in the base settings):
     c2pa-rs clears its built-in EKU list when it loads settings, so dropping it
     records a ProofMode-style parent as `signingCredential.invalid`.
   - Keep one `manifest` entry for the whole pool: the TSA check pools anchors of
     every kind, but OCSP responder chaining reads `manifest` only.
3. Device-test both platforms: a Stage-2 upload's recorded ingredient shows
   `signingCredential.trusted` and `timeStamp.trusted` (`untrusted` means the
   anchors didn't load), and a dev build fed a truncated PEM as
   `trustAnchorsPem` still signs and logs `trust-anchor settings load failed`.
4. Update this section, both `settingsWithTrustAnchors` comments, and the
   verifier's `buildVerifierSettings`, which the native shape mirrors.

#### Thread-local settings → explicit contexts

0.92 also removes `c2pa_load_settings` (`Signer.loadSettings` /
`C2PASigner.loadSettings`) and `c2pa_builder_from_json` (iOS's context-less
`Builder(manifestJSON:)`). c2pa-swift 0.0.14 already moved its context-less
`Reader` onto c2pa-rs **defaults** rather than failing — which is why every read
here passes an explicit context. Expect the same of a context-less `Builder`: it
would sign silently with no `created_assertion_labels`, no auto-timestamp or
thumbnail pins, and no trust pool.

1. **iOS:** build every `Builder` from a context carrying the path's settings
   JSON (`SIGN_SETTINGS_JSON` / `UPDATE_MANIFEST_SETTINGS_JSON`, plus the trust
   pool), as Android already does, then delete the `Signer.loadSettings` calls
   and their defers. That also retires the thread-local merge workarounds: the
   explicit `enabled` pins and the lingering-anchor caveat in
   `settingsWithTrustAnchors`.
2. **Android:** delete the remaining `C2PASigner.loadSettings` calls — every
   Reader and Builder is already context-based, so they're inert today.
3. **The consuming app:** any module of its own that calls the context-less
   `Reader` needs the same explicit context.
4. Device-test thumbnails, auto-timestamping on drains, and `created_assertions`
   on both platforms, not just trust.

## Roadmap

iOS SPM wiring goes through the config plugin because React Native's
`spm_dependency` (0.88) doesn't support a second pod importing the same package,
such as an app's own module that reads manifests with `C2PA`. It builds each
static pod that declares a package into the shared products dir, but rewrites
the moved module map path only for the app target, so a pod that depends on
PhotoAttest can't find it; and two such pods' module maps clash in that one
directory. Once React Native handles both, this module can declare its packages
in the podspec and drop the Podfile injection.

## License

[Apache-2.0](https://github.com/wholeearthlabs/realreel-c2pa/blob/main/LICENSE)
