---
"@realreel/verifier": patch
---

Strip the `, trust list: <uri>` suffix c2pa-rs 0.91 appends to a trusted time-stamp's explanation, so `signature_info.timestamp_authority` stays the TSA's name. Captures from photo-attest builds on c2pa-swift / c2pa-android 0.0.14 record it in the ingredient's validation results.
