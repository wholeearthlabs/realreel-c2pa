---
'@realreel/verifier': patch
---

Runtime dependency bumps: `fastify` 5.11.3 → 5.12.0, `@sentry/node` 10.69.0 → 10.70.0, `google-auth-library` 11.0.0 → 11.0.2, and `@peculiar/asn1-android` / `@peculiar/asn1-x509` 2.8.0 → 2.9.0 (pulling `@peculiar/asn1-schema` 2.9.0).

None of it touches a trust decision. fastify 5.12.0 adds the `Reply.prototype.mediaType` getter and makes `reply.removeHeader()` clear the header off the raw response too — the verifier calls neither, and `/verify` never reads `Content-Type`. `google-auth-library` 11.0.2 is a transitive-dependency refresh on the Play Integrity path. `@sentry/node` 10.70.0 is Cloudflare/Solid fixes plus MCP SDK v2 support, none of it on the Node request path.

The `@peculiar/asn1-*` packages are declared but imported nowhere in the verifier. 2.9.0 is additive upstream (`RelativeObjectIdentifier`, RFC 9925 `id-alg-unsigned`) on top of a TypeScript 7 / oxlint toolchain migration — and that migration also dropped their npm provenance attestation, which 2.8.0 carried. Nothing loads them, so there is no execution risk, but the image still ships them: worth deleting the three outright rather than carrying an unattested chain.

`tsx` and the expo devDependency bumps in this group carry no changeset — the image installs with `--omit=dev` and no published build output moves.
