---
"@realreel/c2pa-trust-core": minor
"@realreel/verifier": minor
---

RealReel no longer trusts its pre-conformance hierarchy ("RealReel Root CA"). The `realreel-legacy` `TRUSTED_ISSUERS` entry and its verifier source are removed, and the client trust-anchor bundle is regenerated without the root. A capture or upload signed under it, whose leaf organization is the bare "RealReel", no longer routes to a trusted source and rejects as `UNTRUSTED_ISSUER`. Enrollments moved to the v2 hierarchy in September 2026, and no upload has been legacy-signed since.
