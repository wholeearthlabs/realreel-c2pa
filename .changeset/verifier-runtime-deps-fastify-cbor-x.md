---
"@realreel/verifier": patch
---

Runtime dependency updates: `fastify` 5.12.5 → 5.12.7, `cbor-x` 1.6.6 → 1.6.7 and `google-auth-library` 11.2.0 → 11.3.1.

fastify 5.12.6 fixes GHSA-389g-gv7q-r4x8 (header `propertyNames` case normalization); the verifier declares no header schema. cbor-x 1.6.7 rejects malformed CBOR it used to report as truncated, which only tightens the App Attest assertion decode. google-auth-library 11.3 nests gaxios 8; it only mints the Play Integrity token, and a token failure still rejects as retryable `VERIFIER_UNAVAILABLE`.
