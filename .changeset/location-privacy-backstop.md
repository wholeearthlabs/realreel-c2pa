---
"@realreel/verifier": minor
---

Add a server-side location-privacy backstop.

The verifier now cross-checks GPS presence in the validated file bytes against
the signed manifest and rejects an upload (with `LOCATION_PRIVACY_VIOLATION`)
whose bytes carry coordinates the manifest doesn't — closing the gap where a
client-side GPS strip on a non-precise ("none"/"general") upload could silently
publish exact coordinates if it ever regressed. The reverse mismatch (manifest
carries coordinates the bytes don't) is reported to telemetry rather than
rejected.
