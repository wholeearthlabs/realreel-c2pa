---
"@realreel/c2pa-trust-core": minor
"@realreel/verifier": patch
---

Add a per-upload content hash so a consumer can block re-posting the same
capture to one profile. The verifier now derives `contentHash` and returns it
in the `/verify` 200 response: `sha256("rrc1:" + identity)`, where `identity`
is the resolved Stage-1 capture manifest label (walked past any interposed TSA
Update Manifests) plus, for video, the signed `c2pa.trimmed`/`c2pa.cropped`
parameters (canonicalized). Anchored to the capture, not the bytes — so the same
capture re-uploaded with any transform collides, while two different video trims
do not. The verifier is stateless about dedup; enforcing uniqueness (e.g. a
`UNIQUE(user_id, content_hash)` index) is the consumer's job.

trust-core gains `buildContentIdentity` and `extractContentExtent` (new
`policies/content-hash`), a shared `extractActionEntries` walk now backing
`extractManifestActions`, and a `DUPLICATE_CONTENT` error code for consumers
that map a uniqueness violation to a user-facing reject.
