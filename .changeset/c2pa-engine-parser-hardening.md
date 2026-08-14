---
'@realreel/verifier': patch
---

Update the C2PA engine: `@contentauth/c2pa-node` 0.8.0 → 0.8.3 and `@contentauth/c2pa-types` 0.7.2 → 0.7.3, which carries `c2pa-rs` 0.90.3 → 0.90.5.

Unlike the last engine bump, this one is worth a redeploy for the read path rather than the builder: 0.90.4 replaces the `mp4` crate with a hardened native BMFF sample reader (CAI-12277), rejects timed-media BMFF Merkle maps that verify against no track, hardens the ID3 v2.3 frame decoder against integer underflow, and tightens URI checks for (data)boxes reached through redactions; 0.90.5 fixes an integer-underflow panic in `read_desc_box` via a JUMD toggle-driven field-size mismatch. Every one of those is a stricter verdict or a removed panic on attacker-supplied bytes — none relaxes a check. The full verification suite passes unchanged against the real fixture media.

The published tarball still bundles a single-arch `linux/amd64` prebuilt with a glibc 2.34 floor, so the image's `--platform=linux/amd64` + `--ignore-scripts` + bookworm assumptions are unchanged.

Also bumps `fastify` 5.11.0 → 5.11.3.
