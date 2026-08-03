---
'@realreel/c2pa-trust-core': patch
'@realreel/photo-attest': patch
'@realreel/verifier': patch
---

Build with TypeScript 7.

TypeScript 7 removed `moduleResolution: node10`, which the CommonJS half of trust-core's dual build used. `bundler` is the only resolution mode TS still accepts alongside `module: CommonJS`, and switching to it is resolution-only: the emitted `dist/commonjs` and `dist/esm` trees are byte-for-byte identical to the TypeScript 5.9 output, so the published package is unchanged. The choice is sound only because the package has no runtime dependencies — every specifier it resolves is a relative `./x.js`.

No source changed. Nothing about the published shape — `main`, `module`, `types`, or any `exports` condition — moved.
