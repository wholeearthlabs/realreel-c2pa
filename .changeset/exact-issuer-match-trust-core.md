---
"@realreel/c2pa-trust-core": minor
---

`findTrustedIssuer` matches a manifest's `signature_info.issuer` against each entry's `issuerMatch` exactly, not as a substring. c2pa-rs fills that field with the signing leaf's subject organization, so every genuine capture still matches; an organization whose name only contains a trusted one no longer does. List order no longer matters.
