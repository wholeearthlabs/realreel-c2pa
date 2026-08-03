---
'@realreel/verifier': patch
---

Read `signature_info.time` through its declared type instead of a local cast, and type-check the test suite in CI.

`readSignatureTime` — the input to the cert-validity gate — reached the field via `as { time?: string }` because `SignatureInfoShape` didn't declare it. It does now, so the cast is gone.

`tsconfig.test.json` was never gated, and five fixtures had drifted from the types they stand in for: `Config` grew `maxAssetBytes`, `TrustConfig` grew `tsaRoots`, `LocationLevel` moved to trust-core, and a fail-closed case deleted a property its inferred type marked required. vitest transpiles with esbuild, which strips types without checking them, so every one of those suites passed green throughout. CI now runs `tsc -p tsconfig.test.json` alongside the src typecheck.
