---
"@realreel/photo-attest": patch
---

The recorded parent-ingredient validation accepts every signing-certificate EKU c2pa-rs allows by default, so a parent whose leaf carries only the C2PA claim-signing or document-signing EKU (such as ProofMode's) is no longer recorded as `signingCredential.invalid`.
