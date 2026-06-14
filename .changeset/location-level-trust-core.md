---
"@realreel/c2pa-trust-core": minor
"@realreel/verifier": patch
---

Move the declared location level into trust-core as the single source of truth:
add `LocationLevel`, `LOCATION_LEVELS`, and the `isLocationLevel` guard. The
verifier's location-privacy gate and POST /verify validation now consume them
instead of a local copy, so the client and verifier can't drift on the level set.
