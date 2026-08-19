---
'@realreel/verifier': patch
---

Drop the four unused `@peculiar/*` dependencies: `@peculiar/asn1-android`, `@peculiar/asn1-schema` and `@peculiar/asn1-x509` (runtime) plus `@peculiar/x509` (dev).

Nothing imports them. They arrived with the initial OSS migration and no TypeScript file in the repo's history has ever referenced one — the verifier reads certificate and attestation structure through `c2pa-node` and the trust-core helpers, and the Android `KeyDescription` parsing that would want them lives in `ca/`, which is Deno and resolves `pkijs`/`asn1js` through its own pinned import map.

Removing them takes 19 packages out of the tree — 8 of them (`@peculiar/asn1-android`, `-schema`, `-x509`, `@peculiar/utils`, `asn1js`, `pvtsutils`, `pvutils`, `tslib`) off the runtime graph and so out of the shipped image. That also retires an unattested link: `@peculiar/asn1-*` 2.9.0 published without the npm provenance attestation 2.8.0 carried, so the image stopped shipping attested copies of those three at the previous release.

No behavior change — the removed packages were never loaded.
