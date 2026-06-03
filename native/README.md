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
    // (1) Wires the iOS Swift Package deps (c2pa-ios `C2PA` + swift-certificates
    //     `X509`) into the Podfile on every prebuild. Required for iOS to build.
    "@realreel/photo-attest",

    // (2) Min platform versions + the JitPack repo c2pa-android resolves from.
    [
      "expo-build-properties",
      {
        ios: { deploymentTarget: "16.0" },          // c2pa-ios requires iOS 16+
        android: {
          minSdkVersion: 28,                          // c2pa-android requires API 28+
          extraMavenRepos: ["https://www.jitpack.io"] // c2pa-android is on JitPack
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

- **iOS deployment target 16.0** — `c2pa-ios` (see `ios/C2PA.version`) requires it.
- **Android `minSdkVersion` 28** — `c2pa-android`'s floor.
- **JitPack** — `c2pa-android` (`com.github.contentauth:c2pa-android`) is distributed
  through JitPack, so the Maven repo must be registered.

The `@realreel/photo-attest` config plugin handles only the part with no other path:
attaching the two iOS Swift Packages to the **PhotoAttest pod target** (pod-target-only,
to dodge the duplicate-symbol explosion that comes from attaching them to the app
target as well). See `plugin/src/index.ts` and `ios/PhotoAttest.podspec` for the why.

## Updating the C2PA version

The pinned `c2pa-ios` version is the single source of truth in `ios/C2PA.version`; the
config plugin reads it at prebuild time. `c2pa-android` is pinned in
`android/build.gradle`. Keep the two in lockstep.

## API

The TypeScript surface (fully typed in `build/index.d.ts`) exposes key lifecycle and
signing calls — e.g. `generateAndAttestKey()`, `getPublicKey()`, `getAttestation()`,
`signC2PACapture()`, `signC2PAUpload()`, and `signTimestampUpdateManifest()`. The web
entry point is a stub that throws (capture/upload are disabled on web).

## Roadmap note

iOS SPM wiring goes through the config plugin above because declarative SPM in Expo
modules still hits duplicate-symbol errors on transitive chains like c2pa-ios's
swift-crypto/swift-asn1 ([expo/expo#37813](https://github.com/expo/expo/issues/37813) —
auto-closed as stale by a bot, *not* fixed; the failure is still unresolved). Once that's
genuinely resolved, this module can move to a declarative `spm_dependency` (the RN 0.75+
podspec helper; alternatively cocoapods-spm's `spm_pkg`) and drop the plugin.

## License

Apache-2.0 — see [LICENSE](./LICENSE).
