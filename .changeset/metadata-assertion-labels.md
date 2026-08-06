---
"@realreel/c2pa-trust-core": minor
---

Add `METADATA_ASSERTION_LABEL` (`c2pa.metadata`) plus `LEGACY_EXIF_ASSERTION_LABEL` / `LEGACY_IPTC_ASSERTION_LABEL` constants. C2PA 2.x deprecates the `stds.exif` / `stds.iptc` metadata assertions; RealReel signers now emit `c2pa.metadata` (JSON-LD) on both stages, while readers keep accepting the legacy labels for wrap-mode third-party parents and pre-cutover media.
