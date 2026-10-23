---
"@realreel/verifier": patch
---

A `CERT_EXPIRED` from the recorded-results gate (the original capture's certificate expired before any trusted timestamp, not this upload's) now has a detail starting `capture: `, so the app can say retrying won't help instead of re-enrolling.
