# @realreel/verifier

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
