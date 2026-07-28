---
"@realreel/verifier": minor
---

Dual trust anchors (v2 `realreel` + `realreel-legacy`) and ledger-backed leaf
validity. checkLedgerTimeBounds replaces the flat 180-day cert-lifetime ceiling
with per-leaf issued_at/expires_at from lookup_signing_key_revocation — apply the
app-side RPC reshape before deploying this image. Adds the ocsp-leaf leaf-status
OCSP responder.
