---
"@realreel/verifier": patch
---

Harden the parent gate: a failure recorded in the parent's ingredient report is rejected as the same failure found live would be, unless it is the parent's own `signingCredential.untrusted` or `.expired` and the verifier's own validation trusts that parent. An interposed timestamp Update Manifest must be signed under a RealReel trust source. The reject detail no longer echoes the recorded explanation.
