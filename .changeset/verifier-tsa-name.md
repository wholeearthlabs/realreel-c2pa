---
"@realreel/verifier": minor
---

Lift the RFC-3161 Time-Stamping Authority provider name onto the sanitized
manifest's `signature_info.timestamp_authority` (per manifest), parsed from
c2pa-rs's `validation_results`, so a viewer can show "Timestamped by …" without
re-reading the asset.
