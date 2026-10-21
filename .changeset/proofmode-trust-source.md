---
"@realreel/c2pa-trust-core": minor
"@realreel/verifier": minor
---

ProofMode's iOS and Android camera apps join the trust list as a wrap-mode capture source: a `proofmode` `TRUSTED_ISSUERS` entry (O "Proofmode Reality Systems LLC", CNs "Proofmode for iOS" and "Proofmode for Android") and a matching `wrap_parent_only` source anchored at the Trufo C2PA Root CA (2025, ECC P384), with Trufo's OCSP responder `https://ocsp.trufo.ai`. The client trust-anchor bundle is regenerated.

`TrustedIssuer.commonNameMatch` now also takes a list, and the new `matchesCommonName` export is the one check `findTrustedIssuer` and the verifier's dispatcher share. Code that reads `commonNameMatch` directly must handle `readonly string[]`.
