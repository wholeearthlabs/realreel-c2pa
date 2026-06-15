# @realreel/verifier

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
