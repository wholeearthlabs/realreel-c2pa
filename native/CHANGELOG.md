# @realreel/photo-attest

## 0.5.0

### Minor Changes

- [`aa7aee0`](https://github.com/wholeearthlabs/realreel-c2pa/commit/aa7aee03a3a8dbaae2f3ff7b399ef02355069f37) Thanks [@boojamya](https://github.com/boojamya)! - Remove `c2pa.cropped` from the Stage-2 action allowlist, the content-hash extent set, and the `Stage2Action` union. The app never emits it, and an allowlisted-but-unemitted action is free attack surface — a declared crop could trim away the telltale edges of a recaptured scene. Any Stage 2 manifest declaring a crop now hard-rejects (`SIGNATURE_INVALID`); no published manifest ever carried the action, so no stored media or `content_hash` is affected.

### Patch Changes

- [`6e533a6`](https://github.com/wholeearthlabs/realreel-c2pa/commit/6e533a644983aeab0354824a646590064b5efc60) Thanks [@boojamya](https://github.com/boojamya)! - Enforce the wrapped parent's hard binding end-to-end, closing the wrap-mode tamper gap (an edited capture with an intact, chain-valid manifest previously verified as Trusted).

  trust-core: new shared binding policy (`findBindingFailureCodes`, `findContentTamperCodes`, `findRecordedBindingViolation`) plus the shared `ALLOWED_UPLOAD_MIME_TYPES`, typed `validation_status` / `validation_results` / ingredient recorded-results shapes, and the `PARENT_BINDING_FAILED` error code. Enforcement is unconditional and fail-closed — content whose binding cannot be verified is not accepted. Known accepted consequence: released mobile SDKs (c2pa-ios ≤ 0.0.12, c2pa-android ≤ 0.0.10, both pre c2pa-rs [#2434](https://github.com/wholeearthlabs/realreel-c2pa/issues/2434)) record a false `bmffHash.mismatch` for genuine Pixel videos, so wrap-mode Pixel VIDEOS are rejected until the SDK bump; acceptance restores itself once bumped SDKs record clean verdicts.

  Verifier (deploys with this release): rejects `PARENT_BINDING_FAILED` unless the Stage-2 `c2pa.ingredient.v3` recorded results carry the positive binding match and no binding failure (fail-closed on an absent record); resolves the PARENT's trust source and enforces `wrap_parent_only` (previously decorative — any pooled anchor, including the TSA roots, could vouch for a "camera"); allowlists + magic-sniffs the client-supplied mimeType before it selects a c2pa-rs asset handler.

  photo-attest: doc-only — the recorded ingredient `validationResults` contract now notes the binding portion is enforced server-side.

## 0.4.0

### Minor Changes

- [`bfae840`](https://github.com/wholeearthlabs/realreel-c2pa/commit/bfae840b3c9b62c6dbb80b9f3012d088a454ab63) Thanks [@boojamya](https://github.com/boojamya)! - Consult the CA + TSA Trust Lists at ingredient ingest (C2PA generator conformance). trust-core now ships `CLIENT_TRUST_ANCHORS_PEM` on the dedicated `@realreel/c2pa-trust-core/trust-anchors` subpath (kept out of the root barrel so non-signing surfaces don't carry the 27 KB pool) — a generated client projection of the trust pool the RealReel verifier loads at boot: content-source CA roots + the C2PA TSA Trust List, minus entries marked `client_bundle: false` in trust-sources.yaml (the general-purpose DigiCert/SSL.com TSA roots stay verifier-private, so the generator never records trust for TSAs off the C2PA TSA Trust List). Byte-lockstep with the verifier's loader is CI-asserted. photo-attest's `signC2PAUpload` and `signTimestampUpdateManifest` accept it as `trustAnchorsPem` and feed it to c2pa-rs, so the parent-ingredient validation recorded into the signed `c2pa.ingredient.v3` `validationResults` sees the real pool instead of running anchorless and permanently recording `signingCredential.untrusted` / `timeStamp.untrusted` for parents that are in fact trusted (e.g. a wrapped Pixel capture's Google chain and Pixel TSA). Failure semantics are availability-first: trust failures against the pool are record-only, and a pool the native c2pa build cannot load degrades the sign to the anchorless path with a warning instead of failing the upload. The base sign settings additionally pin `remote_manifest_fetch`/`ocsp_fetch` off (validating a user-chosen parent must never issue an outbound request), matching the verifier. Omitting the option runs ingredient validation without trust verification.

- [`5001976`](https://github.com/wholeearthlabs/realreel-c2pa/commit/50019764d14e33aed8e5c752d71fd1bebccb866e) Thanks [@boojamya](https://github.com/boojamya)! - Emit the C2PA 2.x `c2pa.metadata` assertion (JSON-LD with `@context`) instead of the deprecated `stds.exif` / `stds.iptc` on both stages — the conformance program rejects deprecated standard assertions on claim-v2 manifests (`validation:no_deprecated_assertions`). Data stays within the c2pa-rs `c2pa.metadata` allowed-field list:
  - Photo GPS is now serialized as XMP GPSCoordinate strings (`"34,16.8548N"`); the separate `exif:GPSLatitudeRef` / `GPSLongitudeRef` fields are gone (not allowlisted — hemisphere folds into the value).
  - Lens identity moves to `exifEX:LensMake` / `exifEX:LensModel`.
  - iOS photos now emit the same explicit key subset as Android instead of dumping every ImageIO key (non-allowlisted keys fail claim-v2 validation).
  - iOS video Make/Model move from `xmpDM:videoCameraManufacturer/-Model` (not allowlisted) to `tiff:Make` / `tiff:Model`.

  Callers that pass `{ action: "c2pa.redacted", parameters: { assertionLabel } }` should target `c2pa.metadata` for parents signed with this version, and keep targeting the legacy label for pre-cutover / third-party (wrap-mode) parents — pick from the parent's observed assertion labels.

- [`0ae8638`](https://github.com/wholeearthlabs/realreel-c2pa/commit/0ae8638806d57527b35872f4a6f2871e8f904c29) Thanks [@boojamya](https://github.com/boojamya)! - Entity-namespace the `Stage2Action` parameter keys (`width` → `org.realreel.width`, likewise `height`, `quality`, `format`, `angle`, `x`, `y`, `start`, `end`). C2PA 2.x §18.15.4.7 requires custom action parameter keys to carry a dot-separated entity namespace, and the conformance checker rejects bare keys (`validation:no_unrecognized_custom_action_parameters`). `c2pa.redacted`'s `assertionLabel` is unchanged — it is a signing-time instruction that native rewrites to the spec's pre-defined `redacted` key, never manifest content. Type-only change; both platforms pass parameters through verbatim.

## 0.3.0

### Minor Changes

- [`54a1908`](https://github.com/wholeearthlabs/realreel-c2pa/commit/54a19082d7929bcf6fe4fbbed20a6693e42ba437) Thanks [@boojamya](https://github.com/boojamya)! - Accept `file://` URIs for every path argument, and report a missing parent capture as `STAGE1_PARENT_UNREADABLE`.

  **Path arguments now take either a plain absolute filesystem path or a local `file://` URI.** Expo's `MediaLibrary.Asset.getUri()`, `ImagePicker`'s `assets[].uri`, `Camera`'s `uri` and `FileSystem`'s `File.uri` all hand back percent-encoded URIs (`Uri.fromFile` on Android, `URL.absoluteString` on iOS), while native needs a bare path. Callers bridging the two by stripping the scheme alone were left with `%20` wherever a path contained a space — and a file that doesn't exist. The failure was easy to miss: every other library in a typical pipeline is URI-aware, so the same file opened fine everywhere else and only the sign failed. Directories with spaces are ordinary in practice (Android Quick Share writes to `Download/Quick Share/`).

  Conversion happens once in the TS bridge (`normalizeMediaPath`, now exported): query/fragment dropped — including the `#asset-metadata` iOS appends to PHAsset video URLs — then percent-decoded. A plain path is passed through untouched and is never decoded, so a literal `%` in a filename still works.

  **`signC2PAUpload` and `signTimestampUpdateManifest` now throw `STAGE1_PARENT_UNREADABLE`, not `C2PA_SIGN_FAILED`, when the parent file is missing.** This matches what that code already documents ("the parent's embedded JUMBF cannot be read (**missing**, corrupted, …)") and what the same functions already throw when the parent's manifest is unreadable. The distinction matters to callers: an absent parent is the user's gallery asset (recapture or re-pick), whereas `C2PA_SIGN_FAILED` means our own signing step broke (retry). Branch on `STAGE1_PARENT_UNREADABLE` if you were matching `C2PA_SIGN_FAILED` for this case.

## 0.2.1

### Patch Changes

- [`0f545fc`](https://github.com/wholeearthlabs/realreel-c2pa/commit/0f545fc05145eea7b6eeb2384690cd8f68f499fe) Thanks [@boojamya](https://github.com/boojamya)! - Fix iOS production archive failing with `"C2PAC.xcframework-ios.signature" couldn't be copied to "Signatures" because an item with the same name already exists`.

  The config plugin now adds an app-target build phase that deletes the duplicate xcframework signature before Xcode's archive packaging step, working around the long-standing SwiftPM `binaryTarget` archive bug (Xcode 15+, still present on Xcode 26). The plugin's existing Podfile SPM injection is unchanged; the new build phase is idempotent and a no-op on non-archive builds.

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
