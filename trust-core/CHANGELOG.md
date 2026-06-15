# @realreel/c2pa-trust-core

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
