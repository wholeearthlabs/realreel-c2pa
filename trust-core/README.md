# @realreel/c2pa-trust-core

[![npm](https://img.shields.io/npm/v/@realreel/c2pa-trust-core)](https://www.npmjs.com/package/@realreel/c2pa-trust-core)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue)](https://github.com/wholeearthlabs/realreel-c2pa/blob/main/LICENSE)

The shared trust-policy layer of the
[RealReel C2PA stack](https://github.com/wholeearthlabs/realreel-c2pa): manifest
shapes, the trust list, action allowlists, and pure policy functions. **No I/O,
no crypto, no native dependencies** — it starts from a parsed C2PA manifest store
and applies the policy.

```
          ┌──────────────────────────────┐
          │  @realreel/c2pa-trust-core   │
          │  shapes · trust list ·       │
          │  allowlists · policies ·     │
          │  error codes                 │
          └──────────────────────────────┘
               ▲                    ▲
     ┌─────────┴─────────┐ ┌────────┴──────────┐
     │ RN client         │ │ Cloud Run verifier│
     │ (preflight gate)  │ │ (full validation) │
     └───────────────────┘ └───────────────────┘
```

**Why it exists:** the client preflight and the server verifier must agree. When
they drift, the preflight passes and the server rejects — the exact failure the
preflight exists to prevent. One package keeps them in lockstep by construction,
and keeps what RealReel considers a trusted capture readable and auditable.

## Install

```bash
npm install @realreel/c2pa-trust-core
```

Ships ESM and CommonJS builds with types.

## Usage

```ts
import {
  CAPTURE_ALLOWED_ACTIONS,
  findDisallowedActions,
  findGenerativeAiSource,
  findTrustedIssuer,
  getActiveManifest,
  type ManifestStoreShape,
} from "@realreel/c2pa-trust-core";

// A capture's manifest-store JSON from your C2PA reader (c2pa-node, c2pa-ios,
// c2pa-android), preflighted before upload: its active manifest is Stage 1.
// (After upload signing, check Stage 2 against REALREEL_UPLOAD_ALLOWED_ACTIONS.)
declare const store: ManifestStoreShape;

const capture = getActiveManifest(store);
if (capture) {
  findTrustedIssuer(capture); // TrustedIssuer | null
  findDisallowedActions(capture, CAPTURE_ALLOWED_ACTIONS); // { disallowed } | null
}
findGenerativeAiSource(store); // GenerativeAiSource | null
```

## Entry points

| Import                                    | Contents                                                                 |
| ----------------------------------------- | ------------------------------------------------------------------------ |
| `@realreel/c2pa-trust-core`               | Everything below except `trust-anchors`.                                  |
| `@realreel/c2pa-trust-core/shapes`        | Typed shapes for the c2pa-rs JSON output.                                 |
| `@realreel/c2pa-trust-core/errors`        | The `VerifyErrorCode` enum.                                               |
| `@realreel/c2pa-trust-core/policies`      | Pure policy functions and constants over parsed manifests (allowlists, structure, binding, AI provenance, …). |
| `@realreel/c2pa-trust-core/trust-list`    | `TRUSTED_ISSUERS`, the curated trusted-camera list, and lookup helpers.   |
| `@realreel/c2pa-trust-core/trust-anchors` | `CLIENT_TRUST_ANCHORS_PEM`, the CA + TSA root pool for ingest — its own subpath so the PEM bundle stays out of every other import. |

## What's not here

Anything that needs I/O, crypto, or platform bindings:

- **Certificate-chain and hash-assertion validation** — server-side, in c2pa-node.
- **Revocation lookup** — server-side, against the certificate ledger.
- **Upload-time app attestation** (App Attest / Play Integrity) — server-side.
- **Reading a manifest from bytes** — the caller's job (c2pa-ios / c2pa-android
  on the client, c2pa-node on the server).

## License

[Apache-2.0](https://github.com/wholeearthlabs/realreel-c2pa/blob/main/LICENSE)
