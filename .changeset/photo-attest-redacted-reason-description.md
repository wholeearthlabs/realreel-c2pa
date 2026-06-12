---
"@realreel/photo-attest": minor
---

Annotate the GPS-redaction action with C2PA `reason` and `description`.

When a user redacts location at upload, the emitted `c2pa.redacted` action now carries the C2PA v2 `reason: "c2pa.PII.present"` (the standard `C2PaReason` controlled value — location counts as PII) and a human-readable `description: "GPS"`, so a manifest viewer can show *why* the `stds.exif`/`stds.iptc` assertion was removed. Added to the iOS and Android signers in lockstep; the fields are signed into the manifest and surface through the verifier's reader into the sanitized `media.c2pa_manifest`. No verifier change is required — the action allowlist matches on action name only.
