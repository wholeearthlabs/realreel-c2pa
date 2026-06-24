# @realreel/verifier

## 0.6.2

### Patch Changes

- [`d6baeff`](https://github.com/wholeearthlabs/realreel-c2pa/commit/d6baeff49a287e0e20309f5ec6c762936374199e) Thanks [@boojamya](https://github.com/boojamya)! - Fix two EXIF metadata-derivation bugs in the photo verifier:
  - **UserComment is no longer dropped.** Spec-compliant EXIF `UserComment` tags store their text after an 8-byte character-code prefix (`ASCII\0\0\0`, `UNICODE\0`, `JIS\0\0\0\0\0`, or 8 NULs). exifr returns the value with that prefix intact, and its NUL bytes tripped the control-byte guard, so the comment was silently discarded from derived metadata. The prefix is now stripped before formatting, so capture breadcrumbs (and any camera UserComment) display again.
  - **GPS coordinates no longer leak into display entries.** exifr emits `latitude`/`longitude`/`altitude` convenience keys even with `gps: false`, and the coordinate-scrub regex didn't match those labels — so precise coordinates could reach `media.metadata` for any GPS-bearing upload. Those keys are now scrubbed; coordinates remain authoritative only from the signed assertion.
  - **Hardening.** Every derived value is clamped to a max length (no oversized comment can bloat `media.metadata`), the video `creation_time` fallback now routes through the same value guard, and exifr's `sanitize` option is pinned explicitly.

## 0.6.1

### Patch Changes

- [`53a1d8a`](https://github.com/wholeearthlabs/realreel-c2pa/commit/53a1d8afcd9a3c84c752e20724ed082c9aea4432) Thanks [@boojamya](https://github.com/boojamya)! - Make the `/verify` asset fetch/buffer ceiling configurable. The size gate
  previously hard-coded a 50 MiB limit (`MAX_ASSET_BYTES`); it now reads
  `config.maxAssetBytes`, overridable via the optional `MAX_ASSET_MIB` env var
  and defaulting to 50 (so default behavior is unchanged). Set it to match the
  asset-storage bucket's `file_size_limit` when that exceeds 50 MiB — otherwise
  an upload whose size lands in the gap band passes Storage and then fails
  verification as oversize. Validated at startup: non-positive or above a 512 MiB
  sanity ceiling throws.

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

- Updated dependencies [[`a7bb35d`](https://github.com/wholeearthlabs/realreel-c2pa/commit/a7bb35d606965ec75f88afd27f3aaf6c896586a4)]:
  - @realreel/c2pa-trust-core@0.3.0

## 0.6.0

### Minor Changes

- [`fba91ab`](https://github.com/wholeearthlabs/realreel-c2pa/commit/fba91abc08666c5063b1e86469fa471db899aa90) Thanks [@boojamya](https://github.com/boojamya)! - Location-privacy gate: enforce the uploader's declared location level. The
  `/verify` request now carries a required `declaredLocation` field (`none` |
  `general` | `precise`, forwarded unsigned). A non-precise level rejects any GPS
  present in either the validated file bytes or the signed assertion with
  `LOCATION_PRIVACY_VIOLATION`. This is additive to the existing bytes-vs-assertion
  spine (kept as the arg-independent backstop) and closes its two blind spots when
  the level is known: a correlated double-regression, and the Direction-2
  assertion-only leak the spine could previously only signal. Strict — a request
  missing or carrying an invalid level is a 400.

### Patch Changes

- [`7e8806d`](https://github.com/wholeearthlabs/realreel-c2pa/commit/7e8806da4195fb24b11e7dbf0acf5e25bf9227d4) Thanks [@boojamya](https://github.com/boojamya)! - Move the declared location level into trust-core as the single source of truth:
  add `LocationLevel`, `LOCATION_LEVELS`, and the `isLocationLevel` guard. The
  verifier's location-privacy gate and POST /verify validation now consume them
  instead of a local copy, so the client and verifier can't drift on the level set.
- Updated dependencies [[`7e8806d`](https://github.com/wholeearthlabs/realreel-c2pa/commit/7e8806da4195fb24b11e7dbf0acf5e25bf9227d4)]:
  - @realreel/c2pa-trust-core@0.2.0

## 0.5.0

### Minor Changes

- [`5c25737`](https://github.com/wholeearthlabs/realreel-c2pa/commit/5c257376b314bd2fdecc94be464cdfeb8e1562a1) Thanks [@boojamya](https://github.com/boojamya)! - Add a server-side location-privacy backstop.

  The verifier now cross-checks GPS presence in the validated file bytes against
  the signed manifest and rejects an upload (with `LOCATION_PRIVACY_VIOLATION`)
  whose bytes carry coordinates the manifest doesn't — closing the gap where a
  client-side GPS strip on a non-precise ("none"/"general") upload could silently
  publish exact coordinates if it ever regressed. The reverse mismatch (manifest
  carries coordinates the bytes don't) is reported to telemetry rather than
  rejected.

### Patch Changes

- Updated dependencies [[`5c25737`](https://github.com/wholeearthlabs/realreel-c2pa/commit/5c257376b314bd2fdecc94be464cdfeb8e1562a1)]:
  - @realreel/c2pa-trust-core@0.1.2

## 0.4.0

### Minor Changes

- [`1189ec9`](https://github.com/wholeearthlabs/realreel-c2pa/commit/1189ec9a8c8bba144e63bae03fa132d7e57469ab) Thanks [@boojamya](https://github.com/boojamya)! - Derive displayed photo/video metadata from the verified upload.

  The `/verify` response now carries a `derived` object (`entries`, `latitude`, `longitude`, `location`, `metadataType`) so the metadata a viewer sees is bound to the verified upload instead of a client-supplied request field. Photos are byte-probed with `exifr`, video with `ffprobe` (the moov-box technical fields aren't in the manifest); GPS comes only from the signed `stds.exif`/`stds.iptc` assertion and is scrubbed from the byte probe, and the location string from the signed `org.realreel.upload` `locationLabel`. `ffprobe` is a new hard runtime dependency, baked into the image as a single sha256-pinned static binary.

## 0.3.0

### Minor Changes

- [`db809bb`](https://github.com/wholeearthlabs/realreel-c2pa/commit/db809bb97cdcdc3787cad2133001818c2d417e91) Thanks [@boojamya](https://github.com/boojamya)! - Lift the RFC-3161 Time-Stamping Authority provider name onto the sanitized
  manifest's `signature_info.timestamp_authority` (per manifest), parsed from
  c2pa-rs's `validation_results`, so a viewer can show "Timestamped by …" without
  re-reading the asset.
