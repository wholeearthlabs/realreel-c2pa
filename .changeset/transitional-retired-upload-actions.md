---
"@realreel/c2pa-trust-core": patch
"@realreel/verifier": patch
---

Accept the retired pre-spec-2.4 action spellings transitionally, so the v0.2 cutover doesn't have to be a flag day.

`REALREEL_UPLOAD_ALLOWED_ACTIONS` now also contains `c2pa.rotated` and `c2pa.resized` (via a separate `TRANSITIONAL_RETIRED_UPLOAD_ACTIONS` set, so deleting them later is one edit). Nothing emits them — the emit side moved to `c2pa.orientation` and `c2pa.resized.proportional` in the previous release.

Without this the cutover is mutually exclusive in both directions: a pre-cutover build's uploads carry the retired names and a post-cutover verifier rejects them, while a post-cutover build's uploads carry the new names and a pre-cutover verifier rejects those. Since every photo upload is downscaled, that is effectively every upload — and a staged store rollout keeps both generations in the field at once, so whichever side moves first breaks the other population. Accepting both lets the verifier deploy and the app release happen independently.

This widens a RealReel ingestion-policy allowlist, not a trust decision: chain validation, revocation, the force-wrap gate and Stage-2 attestation are untouched, and the retired names are exactly what the currently trusted production builds already emit.

Delete `TRANSITIONAL_RETIRED_UPLOAD_ACTIONS` (and redeploy the verifier) once no pre-cutover build is still uploading. The verifier's `policy.test.ts` has two cases marked to flip back to rejections at that point.
