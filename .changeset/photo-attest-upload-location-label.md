---
"@realreel/photo-attest": minor
---

Add an optional `locationLabel` to the Stage-2 upload sign options, signed into the `org.realreel.upload` assertion.

`signC2PAUpload` now accepts `locationLabel?: string` — a reverse-geocoded place label (e.g. `"Phoenix, AZ"`) that the client computes on-device for both general and precise location modes. The iOS and Android signers write it into the `org.realreel.upload` assertion data in lockstep (omitted for "none" mode). This lets the server derive the displayed location string from the signed manifest rather than a client-supplied request field, binding it to the verified upload. No verifier change is required — the field is opaque provenance data (no field-level validation of `org.realreel.upload`); the verifier reads it best-effort.
