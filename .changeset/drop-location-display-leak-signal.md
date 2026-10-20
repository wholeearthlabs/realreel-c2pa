---
"@realreel/verifier": patch
---

The verifier no longer sends the `location_display_leak` Sentry warning. It fired when a precise upload's signed assertion carried GPS its file bytes lacked. That is harmless (a non-precise case is already rejected by the declared-level check) and now expected, for videos whose location comes from the capture's signed metadata. Both location-privacy rejects are unchanged.
