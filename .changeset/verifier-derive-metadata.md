---
"@realreel/verifier": minor
---

Derive displayed photo/video metadata from the verified upload.

The `/verify` response now carries a `derived` object (`entries`, `latitude`, `longitude`, `location`, `metadataType`) so the metadata a viewer sees is bound to the verified upload instead of a client-supplied request field. Photos are byte-probed with `exifr`, video with `ffprobe` (the moov-box technical fields aren't in the manifest); GPS comes only from the signed `stds.exif`/`stds.iptc` assertion and is scrubbed from the byte probe, and the location string from the signed `org.realreel.upload` `locationLabel`. `ffprobe` is a new hard runtime dependency, baked into the image as a single sha256-pinned static binary.
