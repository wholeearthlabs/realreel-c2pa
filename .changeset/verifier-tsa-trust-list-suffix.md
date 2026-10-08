---
"@realreel/verifier": patch
---

Harden the TSA name lifted into `signature_info.timestamp_authority`. Any `, trust list: <uri>` suffix is now stripped whatever the code; c2pa-rs 0.91 appends one to a trusted time-stamp's explanation, which reaches the name once the verifier's own engine moves to 0.91 (#77). Control bytes and unpaired surrogates are also removed from the attacker-influenced CN, because postgres jsonb rejects NUL and lone surrogates and the upload's INSERT would fail.
