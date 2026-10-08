---
"@realreel/photo-attest": minor
---

Native C2PA engines to c2pa-swift (formerly c2pa-ios) and c2pa-android 0.0.14, both on c2pa-rs 0.91.2 (from 0.79.5). This picks up c2pa-rs #2434, so genuine Pixel videos no longer record a false `assertion.bmffHash.mismatch` at Stage-2 ingest, and wrap-mode Pixel videos verify again. Also swift-certificates 1.21.0 (c2pa-swift 0.0.14 needs ≥ 1.19.4; swift-crypto ≥ 4.5.1 for CVE-2026-43823), BouncyCastle 1.86 (five advisories fixed since 1.81) and exifinterface 1.4.2.

c2pa-rs's context-less `Reader` now reads with its defaults, where remote manifest fetch is on, instead of the loaded settings. Every manifest read now passes our settings explicitly, so reading a user-chosen file still never goes to the network.

iOS: a capture or Stage-2 upload signed after an offline drain on the same thread keeps its thumbnails. The drain's `thumbnail.enabled: false` used to persist in c2pa-rs's thread-local settings, because the restored sign settings never set it.

**Consumer changes:** on Android, exclude `/META-INF/LICENSE.md` (`expo-build-properties` → `android.packagingOptions.exclude`), because BouncyCastle 1.85+ ships a duplicate in three jars. `compileSdk` must be 36. On iOS, run `npx expo prebuild --clean` so the Podfile picks up the renamed c2pa-swift package.
