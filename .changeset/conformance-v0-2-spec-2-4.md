---
"@realreel/c2pa-trust-core": minor
"@realreel/photo-attest": minor
"@realreel/verifier": minor
---

C2PA Conformance Program v0.2 / Content Credentials 2.4 signer cutover. Every manifest photo-attest emits changes shape; the trust-core Stage-2 action allowlist changes with it, so the two land together and the app's upload path (which emits the actions) must move in the same release.

photo-attest (both platforms, lockstep):

- `claim_generator_info.specVersion = "2.4.0"` on every manifest (capture, upload, timestamp Update Manifest). SemVer form per spec 2.4 §10.2.2; the Conformance Program requires the key and requires it to match the CPL record.
- Every assertion this module authors — `c2pa.actions.v2`, `c2pa.metadata`, `org.realreel.capture` / `.upload` / `.app_attest` / `.play_integrity` — is now a **created** assertion (`created_assertions`), attributed to the signer. Previously all of them landed in `gathered_assertions` (c2pa-rs's default), which spec 2.4 §10.2.2 defines as "not sourced from the claim generator", and §18.15.2 now requires the actions assertion in `created_assertions` outright. Builder-generated assertions (parent ingredient, claim + ingredient thumbnails, drain `c2pa.time-stamp`) are routed the same way through `builder.created_assertion_labels`. Android Stage 1 threads the sign settings into the builder context like the other paths, so both platforms and all three manifest kinds agree.
- `allActionsIncluded: true` on every actions assertion (Program v0.2 makes the field mandatory). Stage 1 now authors an explicit `c2pa.actions.v2` entry that c2pa-rs prepends `c2pa.created` into. This is a signed claim of completeness — see the `Stage2Action` docs for what it commits the upload path to.
- Stage-2 action vocabulary: `c2pa.rotated` → **`c2pa.orientation`** (the old name was never a pre-defined action and is not entity-namespaced); `c2pa.resized` → **`c2pa.resized.proportional`** (spec 2.4, non-editorial, exempt from `digitalSourceType`); new **`c2pa.edited.metadata`** with an entity-namespaced `org.realreel.removed` list for file-level metadata the upload path removed (GPS strip, re-encode losses). `c2pa.orientation` and `c2pa.trimmed` carry a required `digitalSourceType` (`DigitalSourceTypeUri`), which native copies through; `DIGITAL_SOURCE_TYPE_DIGITAL_CAPTURE` is exported as the fallback value.
- iOS: the Stage-1 video `c2pa.metadata` assertion now signs the camera optics Apple's Camera writes on the VIDEO TRACK (`exifEX:LensModel`, `exif:FNumber`, `exif:FocalLengthIn35mmFilm`), which the upload transcode otherwise destroys. iOS-only by construction (Android captures carry no track-level optics); documented divergence.

trust-core: `REALREEL_UPLOAD_ALLOWED_ACTIONS` is now `c2pa.opened`, `c2pa.orientation`, `c2pa.resized.proportional`, `c2pa.transcoded`, `c2pa.trimmed`, `c2pa.redacted`, `c2pa.edited.metadata`. Hard cutover — the retired spellings are rejected.

verifier (deploys with this release): enforces the new allowlist. Uploads signed by a pre-cutover app build are rejected with `SIGNATURE_INVALID` (pre-launch hard cutover; coordinate the deploy with the app release). The committed device-signed fixtures predate the cutover; their suites re-admit the retired names at the test boundary only, to be deleted at the fixture regeneration pass.
