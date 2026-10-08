# @realreel/photo-attest

Expo native module for **hardware-bound C2PA capture signing** — the client half of
the RealReel C2PA trust stack. It mints a per-device signing key inside secure
hardware, attests the device to a platform root, and signs captures so the
[verifier](https://github.com/wholeearthlabs/realreel-c2pa/tree/main/verifier)
can prove a photo/video came from a genuine, untampered device.

- **iOS** — ECDSA P-256 keypair in the **Secure Enclave** (private key never leaves the
  chip). Device trust is established at enrollment via **App Attest** (`DCAppAttestService`);
  a fresh App Attest assertion is then embedded **per upload** (Stage 2).
- **Android** — ECDSA P-256 keypair in **AndroidKeyStore** (StrongBox when available, TEE
  otherwise). Device trust is established at enrollment via the KeyStore **Key Attestation**
  cert chain; a fresh **Play Integrity** token is then embedded **per upload** (Stage 2).

Stage-1 capture carries no attestation envelope — device trust comes from enrollment, and
the per-upload envelope binds each upload to a fresh single-use server challenge.

> [!IMPORTANT]
> **Reference implementation, best-effort support.** This module is published so the
> RealReel signing path is auditable and reusable — not as a turnkey, supported
> dependency. It ships native Swift/Kotlin that only compiles inside a full Expo +
> Xcode/Gradle app, and it has hard build prerequisites (below). Expect to adapt it.

## Install

```bash
npx expo install @realreel/photo-attest
```

It's an autolinked Expo module — no manual native linking. But it has **build
prerequisites** you must wire up, or the native build will fail.

## Required configuration

Add the config plugin and the build settings to your app config:

```js
// app.config.js / app.json
export default {
  // ...
  plugins: [
    // (1) Wires the iOS Swift Package deps (c2pa-swift `C2PA` + swift-certificates
    //     `X509`) into the Podfile on every prebuild. Required for iOS to build.
    "@realreel/photo-attest",

    // (2) Min platform versions + the JitPack repo c2pa-android resolves from.
    [
      "expo-build-properties",
      {
        ios: { deploymentTarget: "16.0" },          // c2pa-swift requires iOS 16+
        android: {
          minSdkVersion: 28,                          // c2pa-android requires API 28+
          extraMavenRepos: ["https://www.jitpack.io"], // c2pa-android is on JitPack
          packagingOptions: { exclude: ["/META-INF/LICENSE.md"] } // BouncyCastle 1.85+
        }
      }
    ]
  ]
};
```

Then regenerate native projects: `npx expo prebuild --clean`.

### Why these are required (not automated)

The C2PA native libraries impose real constraints, and we keep them explicit so you
stay in control of your app's min versions and repositories:

- **iOS deployment target 16.0** — `c2pa-swift` (see `ios/C2PA.version`) requires it.
- **Android `minSdkVersion` 28** — `c2pa-android`'s floor. Its AAR also needs
  `compileSdk` 36 (Expo SDK 57's default).
- **Exclude `/META-INF/LICENSE.md`** — BouncyCastle 1.85+ ships one in each of
  bcprov, bcpkix and bcutil, and AGP doesn't drop the duplicate, so the Android
  build fails without it.
- **JitPack** — `c2pa-android` (`com.github.contentauth:c2pa-android`) is distributed
  through JitPack, so the Maven repo must be registered.

The `@realreel/photo-attest` config plugin handles only the part with no other path:
attaching the two iOS Swift Packages to the **PhotoAttest pod target** (pod-target-only,
to dodge the duplicate-symbol explosion that comes from attaching them to the app
target as well). See `plugin/src/index.ts` and `ios/PhotoAttest.podspec` for the why.

## Updating the C2PA version

The pinned `c2pa-swift` (formerly `c2pa-ios`) version is the single source of truth in
`ios/C2PA.version`; the config plugin reads it at prebuild time. `c2pa-android` is
pinned in `android/build.gradle`. Keep the two in lockstep.

The plugin's exact swift-certificates pin (`SWIFT_CERT_VERSION`) must satisfy the new
c2pa-swift's `Package.swift` floor, or SPM resolution fails. An existing `ios/` keeps
the old injected Podfile snippet, so regenerate with `npx expo prebuild --clean`.

Check which c2pa-rs each release embeds before bumping: c2pa-swift's
`Configurations/Base.xcconfig` (`C2PA_VERSION`) and c2pa-android's
`library/gradle.properties` (`c2paVersion`). 0.0.14 is c2pa-rs 0.91.2 on both.

### Migrating to `trust.anchors[]` (required before any bump past c2pa-rs 0.91)

`settingsWithTrustAnchors` (both platforms) writes the trust pool as the deprecated
`trust.trust_anchors`. **c2pa-rs 0.92 (scheduled mid-November 2026) removes that
field, and unknown settings keys are ignored** — so bumping onto 0.92 without this
migration signs anchorless with no error, and every recorded parent validation reads
`untrusted`.

Why it isn't migrated yet: on 0.91 the legacy field is the only form parsed when
settings load (`merge_legacy_trust_anchors` in c2pa-rs `sdk/src/settings/mod.rs`),
so a pool the engine can't read throws into the anchorless-with-a-log fallback.
`trust.anchors[]` entries are merged in unchecked and would fail later, past it.

When a c2pa-swift / c2pa-android release moves to c2pa-rs ≥ 0.92:

1. Confirm the new engine parses `trust.anchors[]` at load (`with_string` /
   `from_string` → the anchors get `test_load_trust` / `validate()`). If it still
   doesn't, keep the bad-pool fallback honest another way before migrating, e.g.
   parse the pool natively first.
2. Switch both platforms, in lockstep, to the shape 0.91 derives from the legacy field:

   ```json
   "trust": { "anchors": [ { "trust_kind": "manifest", "trust_uri": "system_anchors", "trust_anchors": "<PEM pool>" } ] }
   ```

   Keep one `manifest` entry for the whole pool: the TSA check pools anchors of
   every kind, but OCSP responder chaining reads `manifest` only.
3. Device-test both platforms: a Stage-2 upload's recorded ingredient shows
   `signingCredential.trusted` and `timeStamp.trusted` (`untrusted` means the anchors
   didn't load), and a dev build fed a truncated PEM as `trustAnchorsPem` still signs
   and logs `trust-anchor settings load failed`.
4. Update this section, both `settingsWithTrustAnchors` comments, and the verifier's
   `buildVerifierSettings`, which the native shape mirrors.

## API

The TypeScript surface (fully typed in `build/index.d.ts`) exposes key lifecycle and
signing calls — e.g. `generateAndAttestKey()`, `getPublicKey()`, `getAttestation()`,
`signC2PACapture()`, `signC2PAUpload()`, and `signTimestampUpdateManifest()`. The web
entry point is a stub that throws (capture/upload are disabled on web).

### Trust anchors at ingest

`signC2PAUpload()` and `signTimestampUpdateManifest()` accept `trustAnchorsPem` — a
concatenated PEM pool (CA + TSA roots) that c2pa-rs validates the parent ingredient
against, recording the outcome into the signed `c2pa.ingredient.v3`
`validationResults` (C2PA generator conformance: the CA and TSA Trust Lists must be
consulted at ingest). Pass `CLIENT_TRUST_ANCHORS_PEM` from
`@realreel/c2pa-trust-core/trust-anchors`. Trust failures — and a pool the native
c2pa build can't load — are recorded/degraded, never thrown; see the option's JSDoc
for details.

### File paths

Every path argument accepts **either** a plain absolute filesystem path **or** a local
`file://` URI, so an Expo `MediaLibrary` / `ImagePicker` / `Camera` / `FileSystem` uri
can be passed straight through:

```ts
// file:///storage/emulated/0/Download/Quick%20Share/capture.jpg
const parent = await new MediaLibrary.Asset(id).getUri();

await PhotoAttest.signC2PAUpload(alias, transformedPath, {
  parentMediaPath: parent,
  certChainPEM,
  actions,
});
```

Don't hand-strip the scheme. Both platforms percent-encode these URIs (`Uri.fromFile`
on Android, `URL.absoluteString` on iOS), so `uri.replace('file://', '')` leaves a `%20`
wherever the path contains a space and the file is then not found — quietly, since the
libraries around it are URI-aware and open the same file fine. The bridge converts for
you (`normalizeMediaPath`, exported if you need it directly); a plain path is passed
through untouched and never decoded.

## Roadmap note

iOS SPM wiring goes through the config plugin above because declarative SPM in Expo
modules still hits duplicate-symbol errors on transitive chains like c2pa-ios's
swift-crypto/swift-asn1 ([expo/expo#37813](https://github.com/expo/expo/issues/37813) —
auto-closed as stale by a bot, *not* fixed; the failure is still unresolved). Once that's
genuinely resolved, this module can move to a declarative `spm_dependency` (the RN 0.75+
podspec helper; alternatively cocoapods-spm's `spm_pkg`) and drop the plugin.

## License

Apache-2.0 — see [LICENSE](./LICENSE).
