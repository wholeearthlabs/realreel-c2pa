---
"@realreel/c2pa-trust-core": minor
"@realreel/photo-attest": minor
"@realreel/verifier": minor
---

Remove `c2pa.cropped` from the Stage-2 action allowlist, the content-hash extent set, and the `Stage2Action` union. The app never emits it, and an allowlisted-but-unemitted action is free attack surface — a declared crop could trim away the telltale edges of a recaptured scene. Any Stage 2 manifest declaring a crop now hard-rejects (`SIGNATURE_INVALID`); no published manifest ever carried the action, so no stored media or `content_hash` is affected.
