# @realreel/photo-attest

## 0.2.0

### Minor Changes

- [`f2e15e9`](https://github.com/wholeearthlabs/realreel-c2pa/commit/f2e15e96b96034b9d4d4b9e6b6eb1fa5830492c8) Thanks [@boojamya](https://github.com/boojamya)! - Drop `captureSource` and `cameraFacing` from the `org.realreel.capture` capture assertion.

  `captureSource` was a hardcoded constant (`"in-app-camera"`) that carried no information — the assertion is only ever emitted by RealReel's own capture signer, so a third-party/wrap-mode parent never sets it. `cameraFacing` (`front`/`back`) was informational only and was never read by the verifier or trust list. Both are removed from the iOS and Android signers and from the `SignC2PACaptureOptions` bridge in lockstep; the assertion now carries `capturerUuid`, `deviceManufacturer`, `deviceModel`, `osVersion`, `appVersion`, and `deviceTrustLevel`.

- [`86ca2fb`](https://github.com/wholeearthlabs/realreel-c2pa/commit/86ca2fb210fc4210c3519657ca66651f202e757b) Thanks [@boojamya](https://github.com/boojamya)! - Annotate the GPS-redaction action with C2PA `reason` and `description`.

  When a user redacts location at upload, the emitted `c2pa.redacted` action now carries the C2PA v2 `reason: "c2pa.PII.present"` (the standard `C2PaReason` controlled value — location counts as PII) and a human-readable `description: "GPS"`, so a manifest viewer can show _why_ the `stds.exif`/`stds.iptc` assertion was removed. Added to the iOS and Android signers in lockstep; the fields are signed into the manifest and surface through the verifier's reader into the sanitized `media.c2pa_manifest`. No verifier change is required — the action allowlist matches on action name only.

- [`1189ec9`](https://github.com/wholeearthlabs/realreel-c2pa/commit/1189ec9a8c8bba144e63bae03fa132d7e57469ab) Thanks [@boojamya](https://github.com/boojamya)! - Add an optional `locationLabel` to the Stage-2 upload sign options, signed into the `org.realreel.upload` assertion.

  `signC2PAUpload` now accepts `locationLabel?: string` — a reverse-geocoded place label (e.g. `"Phoenix, AZ"`) that the client computes on-device for both general and precise location modes. The iOS and Android signers write it into the `org.realreel.upload` assertion data in lockstep (omitted for "none" mode). This lets the server derive the displayed location string from the signed manifest rather than a client-supplied request field, binding it to the verified upload. No verifier change is required — the field is opaque provenance data (no field-level validation of `org.realreel.upload`); the verifier reads it best-effort.

## 0.1.2

### Patch Changes

- [`fa2ca42`](https://github.com/wholeearthlabs/realreel-c2pa/commit/fa2ca421e2ca0bc9d2ca0dbcbf2134b6391174ed) Thanks [@boojamya](https://github.com/boojamya)! - Fix packaging: include the compiled Expo config plugin (`plugin/build`) in the published tarball.

  `app.plugin.js` does `require('./plugin/build')`, but the publish lifecycle (`expo-module prepublishOnly` = clean + build the native module) never built the config plugin, so every clean publish shipped without it. Consumers then crashed on any Expo app-config read (`expo start`, `expo prebuild`, web export) with `PluginError: Cannot find module './plugin/build'`.

  The config plugin is now built during `prepack`, a CI gate packs the tarball and fails if `plugin/build` is absent, and the plugin TypeScript compiles cleanly (`@types/node`).

## 0.1.1

### Patch Changes

- [`cc88a26`](https://github.com/wholeearthlabs/realreel-c2pa/commit/cc88a261247f48d61b5fbc702282b5fdafb5b79b) Thanks [@boojamya](https://github.com/boojamya)! - `overwriteMediaLibraryAsset`: accept SDK-56 `expo-media-library` asset ids.

  The redesigned (SDK 56) `expo-media-library` API changed the format of `Asset.id`: iOS now returns `ph://<localIdentifier>` and Android a `content://…` MediaStore uri (previously a bare PHAsset localIdentifier and a bare numeric MediaStore `_ID`, respectively). `overwriteMediaLibraryAsset` still expected the legacy form, so it could no longer locate the asset and failed with `ASSET_NOT_FOUND`.

  Both platforms now normalize the id before lookup — iOS strips the `ph://` scheme, Android parses the content uri's last path segment to the row id.
