---
"@realreel/c2pa-trust-core": patch
"@realreel/verifier": patch
---

The C2PA TSA Trust List is refreshed to upstream as of 2026-10-29, adding eight certificates: Snowball (ECC P-384 root and TSA ICA), Encypher (2026 root and TSA issuing CA), TrustAsia (RSA and ECC roots), Castlabs (ECC P-384 root) and NETLOCK (ECC TSA G2 CA 1). Timestamps from these TSAs now validate as trusted. The client trust-anchor bundle is regenerated.
