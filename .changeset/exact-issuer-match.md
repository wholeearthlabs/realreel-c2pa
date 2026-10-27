---
"@realreel/verifier": patch
---

A capture resolves to its trust source only when the signer's organization equals the source's `issuerMatch` exactly, matching `findTrustedIssuer`. The OCSP re-check of a third-party capture may contact only that capture's own source's responders, not every source's.
