---
"@realreel/photo-attest": patch
---

The iOS module builds against Expo SDK 58, whose `Exception` declares a `message` property that clashed with the module's error type.
