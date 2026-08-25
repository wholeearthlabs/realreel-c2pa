---
"@realreel/verifier": patch
---

Runtime dependency bumps: `@contentauth/c2pa-node` 0.8.3 → 0.9.1 and `fastify` 5.12.0 → 5.12.1.

The c2pa-node bump moves the embedded engine from c2pa-rs 0.90.5 to 0.90.15 — the same c2pa-rs the pinned `c2patool` 0.27.15 already runs. The crJSON harness's engine cross-check has been comparing a 0.90.5 engine against a 0.90.15 serializer and asserting only that the minor matched; the two sides are now the same patch, so agreement means the same code rather than the same minor. `ENGINE_C2PA_RS` (`src/harness/crjson.ts`), the pin test and the `CRJSON_HARNESS.md` version table move with it. c2patool, `ci.yml` and the Dockerfile are unchanged.

The ten intervening c2pa-rs releases are hardening and validation fixes, several on paths the verifier depends on: `inputTo` ingredients are now validated against manifest tampering (0.90.12), which is the relationship the force-wrap model puts a foreign parent in; deep recursion in update manifests with parent cycles (0.90.15) and exponential re-verification of diamond `inputTo` graphs (0.90.14) are both bounded; an out-of-range `GeneralizedTime` no longer panics (0.90.11). 0.90.9 adds a read path for c2md JUMBF-data manifests — new surface, but `verify()` gates on the jpeg/isobmff MIME allowlist before an asset reaches a handler.

No API change: `Reader` is identical between the two versions. `createTrustSettings` and `settingsToJson` moved into the new `@contentauth/c2pa-utilities` and are re-exported from c2pa-node's index, and `settingsToJson` still serializes exactly as before, so `buildVerifierSettings` produces the same `trust_anchors` / `verify_trust_list` / `remote_manifest_fetch` / `ocsp_fetch` document. c2pa-node 0.9.0 also added a `resolveSettings` entry point that fetches URL-valued trust settings over the network; the verifier does not call it, and `verify.ts` now says why. The Reader's new asset-size guard caps at 10 GB, well above the 512 MiB `MAX_ASSET_MIB` ceiling.

fastify 5.12.1 is a security release: GHSA-3m5p-2c4r-xxw2 (X-Forwarded-\* spoofing under a numeric `trustProxy` hop count) does not apply — the verifier never sets `trustProxy` — and GHSA-w2qp-rph6-63g4 is a schema-validation bypass for root primitive coercion, which no verifier route schema uses.

The `vitest`, `@changesets/cli` and `expo-modules-core` bumps in this group are devDependencies and carry no changeset.
