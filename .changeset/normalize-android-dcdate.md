---
"@realreel/photo-attest": patch
---

Normalize Android's video `dc:date` to extended ISO 8601 UTC. MediaMetadataRetriever returns the container date in basic form (`20260509T203821.000Z`), so the Android Stage-2 `c2pa.metadata` assertion disagreed in shape with iOS. Parsed values re-serialize through the shared formatter; an unrecognized camera string still passes through verbatim.
