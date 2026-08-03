---
'@realreel/c2pa-trust-core': patch
---

Declare `alg`, `time`, and `timeObject` on `SignatureInfoShape`.

All three are fields c2pa-rs actually emits and consumers actually read — the verifier's cert-validity gate reads `time` to decide whether a signature predates `now`, and its sanitizer surfaces all three to viewers. Because the interface didn't declare them, both reached the data through local casts (`active.signature_info as { time?: string }`), which is precisely the pattern this file exists to remove. Additive and optional, so no consumer breaks.
