---
"@realreel/verifier": minor
---

Location-privacy gate: enforce the uploader's declared location level. The
`/verify` request now carries a required `declaredLocation` field (`none` |
`general` | `precise`, forwarded unsigned). A non-precise level rejects any GPS
present in either the validated file bytes or the signed assertion with
`LOCATION_PRIVACY_VIOLATION`. This is additive to the existing bytes-vs-assertion
spine (kept as the arg-independent backstop) and closes its two blind spots when
the level is known: a correlated double-regression, and the Direction-2
assertion-only leak the spine could previously only signal. Strict — a request
missing or carrying an invalid level is a 400.
