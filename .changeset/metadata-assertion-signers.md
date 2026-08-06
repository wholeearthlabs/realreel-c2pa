---
"@realreel/photo-attest": minor
---

Emit the C2PA 2.x `c2pa.metadata` assertion (JSON-LD with `@context`) instead of the deprecated `stds.exif` / `stds.iptc` on both stages — the conformance program rejects deprecated standard assertions on claim-v2 manifests (`validation:no_deprecated_assertions`). Data stays within the c2pa-rs `c2pa.metadata` allowed-field list:

- Photo GPS is now serialized as XMP GPSCoordinate strings (`"34,16.8548N"`); the separate `exif:GPSLatitudeRef` / `GPSLongitudeRef` fields are gone (not allowlisted — hemisphere folds into the value).
- Lens identity moves to `exifEX:LensMake` / `exifEX:LensModel`.
- iOS photos now emit the same explicit key subset as Android instead of dumping every ImageIO key (non-allowlisted keys fail claim-v2 validation).
- iOS video Make/Model move from `xmpDM:videoCameraManufacturer/-Model` (not allowlisted) to `tiff:Make` / `tiff:Model`.

Callers that pass `{ action: "c2pa.redacted", parameters: { assertionLabel } }` should target `c2pa.metadata` for parents signed with this version, and keep targeting the legacy label for pre-cutover / third-party (wrap-mode) parents — pick from the parent's observed assertion labels.
