---
"@realreel/verifier": patch
---

Harden the parent gate: a failure recorded in the parent's ingredient report is rejected as the same failure found live would be, unless the verifier's own validation trusts the parent. The reject detail no longer echoes the recorded explanation.
