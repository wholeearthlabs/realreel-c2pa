# @realreel/c2pa-trust-core

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
