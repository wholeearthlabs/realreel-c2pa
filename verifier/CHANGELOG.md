# @realreel/verifier

## 0.3.0

### Minor Changes

- [`db809bb`](https://github.com/wholeearthlabs/realreel-c2pa/commit/db809bb97cdcdc3787cad2133001818c2d417e91) Thanks [@boojamya](https://github.com/boojamya)! - Lift the RFC-3161 Time-Stamping Authority provider name onto the sanitized
  manifest's `signature_info.timestamp_authority` (per manifest), parsed from
  c2pa-rs's `validation_results`, so a viewer can show "Timestamped by …" without
  re-reading the asset.
