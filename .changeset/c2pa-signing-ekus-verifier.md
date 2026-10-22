---
"@realreel/verifier": patch
---

Accept every signing-certificate EKU c2pa-rs allows by default, including C2PA claim signing and document signing. A capture leaf carrying only those, such as ProofMode's, previously failed as `signingCredential.invalid`.
