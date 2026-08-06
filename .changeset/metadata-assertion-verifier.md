---
"@realreel/verifier": patch
---

Read GPS from the C2PA 2.x `c2pa.metadata` assertion (with permanent fallback to the deprecated `stds.exif` / `stds.iptc` for pre-cutover app builds and third-party wrap-mode parents), and parse XMP GPSCoordinate strings (`"34,16.8548N"`) in addition to signed decimals. Must be deployed BEFORE any `@realreel/photo-attest` ≥ 0.4.0 signer ships — otherwise the location-privacy backstop hard-rejects precise-location uploads (`LOCATION_PRIVACY_VIOLATION`).
