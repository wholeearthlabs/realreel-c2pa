# @realreel/c2pa-trust-core

## 0.7.1

### Patch Changes

- [`81ad36b`](https://github.com/wholeearthlabs/realreel-c2pa/commit/81ad36b40ca1c02928853530667cc6ba7bbec5e4) Thanks [@boojamya](https://github.com/boojamya)! - Accept the retired pre-spec-2.4 action spellings transitionally, so the v0.2 cutover doesn't have to be a flag day.

  `REALREEL_UPLOAD_ALLOWED_ACTIONS` now also contains `c2pa.rotated` and `c2pa.resized` (via a separate `TRANSITIONAL_RETIRED_UPLOAD_ACTIONS` set, so deleting them later is one edit). Nothing emits them — the emit side moved to `c2pa.orientation` and `c2pa.resized.proportional` in the previous release.

  Without this the cutover is mutually exclusive in both directions: a pre-cutover build's uploads carry the retired names and a post-cutover verifier rejects them, while a post-cutover build's uploads carry the new names and a pre-cutover verifier rejects those. Since every photo upload is downscaled, that is effectively every upload — and a staged store rollout keeps both generations in the field at once, so whichever side moves first breaks the other population. Accepting both lets the verifier deploy and the app release happen independently.

  This widens a RealReel ingestion-policy allowlist, not a trust decision: chain validation, revocation, the force-wrap gate and Stage-2 attestation are untouched, and the retired names are exactly what the currently trusted production builds already emit.

  Delete `TRANSITIONAL_RETIRED_UPLOAD_ACTIONS` (and redeploy the verifier) once no pre-cutover build is still uploading. The verifier's `policy.test.ts` has two cases marked to flip back to rejections at that point.

## 0.7.0

### Minor Changes

- [#44](https://github.com/wholeearthlabs/realreel-c2pa/pull/44) [`1dbadcb`](https://github.com/wholeearthlabs/realreel-c2pa/commit/1dbadcb0ee74747521309ae68bb8740e29f12985) Thanks [@boojamya](https://github.com/boojamya)! - C2PA Conformance Program v0.2 / Content Credentials 2.4 signer cutover. Every manifest photo-attest emits changes shape; the trust-core Stage-2 action allowlist changes with it, so the two land together and the app's upload path (which emits the actions) must move in the same release.

  photo-attest (both platforms, lockstep):
  - `claim_generator_info.specVersion = "2.4.0"` on every manifest (capture, upload, timestamp Update Manifest). SemVer form per spec 2.4 §10.2.2; the Conformance Program requires the key and requires it to match the CPL record.
  - Every assertion this module authors — `c2pa.actions.v2`, `c2pa.metadata`, `org.realreel.capture` / `.upload` / `.app_attest` / `.play_integrity` — is now a **created** assertion (`created_assertions`), attributed to the signer. Previously all of them landed in `gathered_assertions` (c2pa-rs's default), which spec 2.4 §10.2.2 defines as "not sourced from the claim generator", and §18.15.2 now requires the actions assertion in `created_assertions` outright. Builder-generated assertions (parent ingredient, claim + ingredient thumbnails, drain `c2pa.time-stamp`) are routed the same way through `builder.created_assertion_labels`. Android Stage 1 threads the sign settings into the builder context like the other paths, so both platforms and all three manifest kinds agree.
  - `allActionsIncluded: true` on every actions assertion (Program v0.2 makes the field mandatory). Stage 1 now authors an explicit `c2pa.actions.v2` entry that c2pa-rs prepends `c2pa.created` into. This is a signed claim of completeness — see the `Stage2Action` docs for what it commits the upload path to.
  - Stage-2 action vocabulary: `c2pa.rotated` → **`c2pa.orientation`** (the old name was never a pre-defined action and is not entity-namespaced); `c2pa.resized` → **`c2pa.resized.proportional`** (spec 2.4, non-editorial, exempt from `digitalSourceType`); new **`c2pa.edited.metadata`** with an entity-namespaced `org.realreel.removed` list for file-level metadata the upload path removed (GPS strip, re-encode losses). `c2pa.orientation` and `c2pa.trimmed` carry a required `digitalSourceType` (`DigitalSourceTypeUri`), which native copies through; `DIGITAL_SOURCE_TYPE_DIGITAL_CAPTURE` is exported as the fallback value.
  - iOS: the Stage-1 video `c2pa.metadata` assertion now signs the camera optics Apple's Camera writes on the VIDEO TRACK (`exifEX:LensModel`, `exif:FNumber`, `exif:FocalLengthIn35mmFilm`), which the upload transcode otherwise destroys. iOS-only by construction (Android captures carry no track-level optics); documented divergence.

  trust-core: `REALREEL_UPLOAD_ALLOWED_ACTIONS` is now `c2pa.opened`, `c2pa.orientation`, `c2pa.resized.proportional`, `c2pa.transcoded`, `c2pa.trimmed`, `c2pa.redacted`, `c2pa.edited.metadata`. Hard cutover — the retired spellings are rejected.

  verifier (deploys with this release): enforces the new allowlist. Uploads signed by a pre-cutover app build are rejected with `SIGNATURE_INVALID` (pre-launch hard cutover; coordinate the deploy with the app release). The committed device-signed fixtures predate the cutover; their suites re-admit the retired names at the test boundary only, to be deleted at the fixture regeneration pass.

## 0.6.0

### Minor Changes

- [`aa7aee0`](https://github.com/wholeearthlabs/realreel-c2pa/commit/aa7aee03a3a8dbaae2f3ff7b399ef02355069f37) Thanks [@boojamya](https://github.com/boojamya)! - Remove `c2pa.cropped` from the Stage-2 action allowlist, the content-hash extent set, and the `Stage2Action` union. The app never emits it, and an allowlisted-but-unemitted action is free attack surface — a declared crop could trim away the telltale edges of a recaptured scene. Any Stage 2 manifest declaring a crop now hard-rejects (`SIGNATURE_INVALID`); no published manifest ever carried the action, so no stored media or `content_hash` is affected.

### Patch Changes

- [`6e533a6`](https://github.com/wholeearthlabs/realreel-c2pa/commit/6e533a644983aeab0354824a646590064b5efc60) Thanks [@boojamya](https://github.com/boojamya)! - Enforce the wrapped parent's hard binding end-to-end, closing the wrap-mode tamper gap (an edited capture with an intact, chain-valid manifest previously verified as Trusted).

  trust-core: new shared binding policy (`findBindingFailureCodes`, `findContentTamperCodes`, `findRecordedBindingViolation`) plus the shared `ALLOWED_UPLOAD_MIME_TYPES`, typed `validation_status` / `validation_results` / ingredient recorded-results shapes, and the `PARENT_BINDING_FAILED` error code. Enforcement is unconditional and fail-closed — content whose binding cannot be verified is not accepted. Known accepted consequence: released mobile SDKs (c2pa-ios ≤ 0.0.12, c2pa-android ≤ 0.0.10, both pre c2pa-rs [#2434](https://github.com/wholeearthlabs/realreel-c2pa/issues/2434)) record a false `bmffHash.mismatch` for genuine Pixel videos, so wrap-mode Pixel VIDEOS are rejected until the SDK bump; acceptance restores itself once bumped SDKs record clean verdicts.

  Verifier (deploys with this release): rejects `PARENT_BINDING_FAILED` unless the Stage-2 `c2pa.ingredient.v3` recorded results carry the positive binding match and no binding failure (fail-closed on an absent record); resolves the PARENT's trust source and enforces `wrap_parent_only` (previously decorative — any pooled anchor, including the TSA roots, could vouch for a "camera"); allowlists + magic-sniffs the client-supplied mimeType before it selects a c2pa-rs asset handler.

  photo-attest: doc-only — the recorded ingredient `validationResults` contract now notes the binding portion is enforced server-side.

## 0.5.0

### Minor Changes

- [`bfae840`](https://github.com/wholeearthlabs/realreel-c2pa/commit/bfae840b3c9b62c6dbb80b9f3012d088a454ab63) Thanks [@boojamya](https://github.com/boojamya)! - Consult the CA + TSA Trust Lists at ingredient ingest (C2PA generator conformance). trust-core now ships `CLIENT_TRUST_ANCHORS_PEM` on the dedicated `@realreel/c2pa-trust-core/trust-anchors` subpath (kept out of the root barrel so non-signing surfaces don't carry the 27 KB pool) — a generated client projection of the trust pool the RealReel verifier loads at boot: content-source CA roots + the C2PA TSA Trust List, minus entries marked `client_bundle: false` in trust-sources.yaml (the general-purpose DigiCert/SSL.com TSA roots stay verifier-private, so the generator never records trust for TSAs off the C2PA TSA Trust List). Byte-lockstep with the verifier's loader is CI-asserted. photo-attest's `signC2PAUpload` and `signTimestampUpdateManifest` accept it as `trustAnchorsPem` and feed it to c2pa-rs, so the parent-ingredient validation recorded into the signed `c2pa.ingredient.v3` `validationResults` sees the real pool instead of running anchorless and permanently recording `signingCredential.untrusted` / `timeStamp.untrusted` for parents that are in fact trusted (e.g. a wrapped Pixel capture's Google chain and Pixel TSA). Failure semantics are availability-first: trust failures against the pool are record-only, and a pool the native c2pa build cannot load degrades the sign to the anchorless path with a warning instead of failing the upload. The base sign settings additionally pin `remote_manifest_fetch`/`ocsp_fetch` off (validating a user-chosen parent must never issue an outbound request), matching the verifier. Omitting the option runs ingredient validation without trust verification.

- [`5001976`](https://github.com/wholeearthlabs/realreel-c2pa/commit/50019764d14e33aed8e5c752d71fd1bebccb866e) Thanks [@boojamya](https://github.com/boojamya)! - Add `METADATA_ASSERTION_LABEL` (`c2pa.metadata`) plus `LEGACY_EXIF_ASSERTION_LABEL` / `LEGACY_IPTC_ASSERTION_LABEL` constants. C2PA 2.x deprecates the `stds.exif` / `stds.iptc` metadata assertions; RealReel signers now emit `c2pa.metadata` (JSON-LD) on both stages, while readers keep accepting the legacy labels for wrap-mode third-party parents and pre-cutover media.

## 0.4.1

### Patch Changes

- [#28](https://github.com/wholeearthlabs/realreel-c2pa/pull/28) [`a6f8caa`](https://github.com/wholeearthlabs/realreel-c2pa/commit/a6f8caa2f34c925425f5f19af49c8dc775548617) Thanks [@boojamya](https://github.com/boojamya)! - Build with TypeScript 7.

  TypeScript 7 removed `moduleResolution: node10`, which the CommonJS half of trust-core's dual build used. `bundler` is the only resolution mode TS still accepts alongside `module: CommonJS`, and switching to it is resolution-only: the emitted `dist/commonjs` and `dist/esm` trees are byte-for-byte identical to the TypeScript 5.9 output, so the published package is unchanged. The choice is sound only because the package has no runtime dependencies — every specifier it resolves is a relative `./x.js`.

  No source changed. Nothing about the published shape — `main`, `module`, `types`, or any `exports` condition — moved.

  `photo-attest` and the verifier move to TypeScript 7 in the same change, but only as a dev dependency: their build output is unaffected, so neither carries a changeset for it.

- [#29](https://github.com/wholeearthlabs/realreel-c2pa/pull/29) [`ac8ac9b`](https://github.com/wholeearthlabs/realreel-c2pa/commit/ac8ac9bb98bec927d03994924f88a5d17d852868) Thanks [@boojamya](https://github.com/boojamya)! - Declare `alg`, `time`, and `timeObject` on `SignatureInfoShape`.

  All three are fields c2pa-rs actually emits and consumers actually read — the verifier's cert-validity gate reads `time` to decide whether a signature predates `now`, and its sanitizer surfaces all three to viewers. Because the interface didn't declare them, both reached the data through local casts (`active.signature_info as { time?: string }`), which is precisely the pattern this file exists to remove. Additive and optional, so no consumer breaks.

## 0.4.0

### Minor Changes

- [`97f0341`](https://github.com/wholeearthlabs/realreel-c2pa/commit/97f03414f091baab315e84734695a15b94920eae) Thanks [@boojamya](https://github.com/boojamya)! - Dual RealReel trust anchors for the conformant-hierarchy cutover.

  The `realreel` entry now matches the v2 hierarchy (issuer "Whole Earth
  Labs LLC", root "RealReel C2PA Root CA"); a new `realreel-legacy` entry
  carries the previous pins (issuer "RealReel", root "RealReel Root CA")
  for every enrollment fielded before the issuance flip. The bare-O
  surfaces are mutually non-substring; full-DN surfaces contain "RealReel"
  via the v2 CN, so `realreel` is deliberately declared first
  (first-match) — tests pin both the order and the full-DN routing.

  Behavior note for consumers: manifests signed under the legacy hierarchy
  now resolve to `findTrustedIssuer(...).id === "realreel-legacy"` instead
  of `"realreel"`. Trusted/untrusted decisions are unchanged; only code
  that keys on the entry id (none in RealReel's client or verifier) would
  notice. `realreel-legacy` will be removed once the last legacy leaf
  expires after the flip.

## 0.3.0

### Minor Changes

- [`a7bb35d`](https://github.com/wholeearthlabs/realreel-c2pa/commit/a7bb35d606965ec75f88afd27f3aaf6c896586a4) Thanks [@boojamya](https://github.com/boojamya)! - Add a per-upload content hash so a consumer can block re-posting the same
  capture to one profile. The verifier now derives `contentHash` and returns it
  in the `/verify` 200 response: `sha256("rrc1:" + identity)`, where `identity`
  is the resolved Stage-1 capture manifest label (walked past any interposed TSA
  Update Manifests) plus, for video, the signed `c2pa.trimmed`/`c2pa.cropped`
  parameters (canonicalized). Anchored to the capture, not the bytes — so the same
  capture re-uploaded with any transform collides, while two different video trims
  do not. The verifier is stateless about dedup; enforcing uniqueness (e.g. a
  `UNIQUE(user_id, content_hash)` index) is the consumer's job.

  trust-core gains `buildContentIdentity` and `extractContentExtent` (new
  `policies/content-hash`), a shared `extractActionEntries` walk now backing
  `extractManifestActions`, and a `DUPLICATE_CONTENT` error code for consumers
  that map a uniqueness violation to a user-facing reject.

## 0.2.0

### Minor Changes

- [`7e8806d`](https://github.com/wholeearthlabs/realreel-c2pa/commit/7e8806da4195fb24b11e7dbf0acf5e25bf9227d4) Thanks [@boojamya](https://github.com/boojamya)! - Move the declared location level into trust-core as the single source of truth:
  add `LocationLevel`, `LOCATION_LEVELS`, and the `isLocationLevel` guard. The
  verifier's location-privacy gate and POST /verify validation now consume them
  instead of a local copy, so the client and verifier can't drift on the level set.

## 0.1.2

### Patch Changes

- [`5c25737`](https://github.com/wholeearthlabs/realreel-c2pa/commit/5c257376b314bd2fdecc94be464cdfeb8e1562a1) Thanks [@boojamya](https://github.com/boojamya)! - Add the `LOCATION_PRIVACY_VIOLATION` verify-error code, returned when an
  upload's file bytes carry GPS coordinates its signed manifest doesn't.
