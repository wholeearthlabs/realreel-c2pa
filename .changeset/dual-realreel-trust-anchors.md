---
"@realreel/c2pa-trust-core": minor
---

Dual RealReel trust anchors for the conformant-hierarchy cutover.

The `realreel` entry now matches the v2 hierarchy (issuer "Whole Earth
Labs LLC", root "RealReel C2PA Root CA"); a new `realreel-legacy` entry
carries the previous pins (issuer "RealReel", root "RealReel Root CA")
for every enrollment fielded before the issuance flip. The bare-O
surfaces are mutually non-substring; full-DN surfaces contain "RealReel"
via the v2 CN, so `realreel` is deliberately declared first
(first-match) — tests pin both the order and the full-DN routing.

Behavior note for consumers: manifests signed under the legacy hierarchy
now resolve to `findTrustedIssuer(...).id === "realreel-legacy"` instead
of `"realreel"`. Trusted/untrusted decisions are unchanged; only code
that keys on the entry id (none in RealReel's client or verifier) would
notice. `realreel-legacy` will be removed once the last legacy leaf
expires after the flip.
