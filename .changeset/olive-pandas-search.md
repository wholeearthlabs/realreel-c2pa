---
'@realreel/verifier': minor
---

Update the C2PA engine: `@contentauth/c2pa-node` 0.5.5 → 0.8.0 and `@contentauth/c2pa-types` 0.4.4 → 0.7.2, which carries `c2pa-rs` 0.89.x → 0.90.0.

The upstream changes are builder-side (archive-metadata stripping, experimental builder reduction methods, prebuilt-binary distribution fixes) — this service only reads and validates, and the full verification suite passes unchanged against the real fixture media. The `c2pa-rs` bump is the part worth a redeploy: validation behavior lives there.

The published tarball still bundles a single-arch `linux/amd64` prebuilt with a glibc 2.34 floor, so the image's `--platform=linux/amd64` + `--ignore-scripts` + bookworm assumptions are unchanged.

Also bumps `fastify` 5.8.5 → 5.11.0, `@peculiar/asn1-android` / `@peculiar/asn1-x509` 2.7.0 → 2.8.0, and `cbor-x` 1.6.4 → 1.6.5.
