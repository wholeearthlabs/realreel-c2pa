# @realreel/c2pa-trust-core

Shared trust-policy layer between the RealReel React Native client and the Cloud Run C2PA verifier.

## What this is

A pure-TypeScript package containing the data shapes, trust list, and pure policy functions that both validators apply to a parsed C2PA manifest store. No I/O, no crypto, no native dependencies.

```
┌──────────────────────────────────────┐
│  @realreel/c2pa-trust-core           │
│                                      │
│  • Manifest shapes                   │
│  • Trust list (cameras / PEMs)       │
│  • Action allowlists                 │
│  • Pure policy functions             │
│  • Error codes                       │
└──────────────────────────────────────┘
       ▲                ▲
       │                │
┌──────┴────────┐  ┌────┴────────────────┐
│ RN client     │  │ Cloud Run verifier  │
│ (preflight)   │  │ (full validation)   │
└───────────────┘  └─────────────────────┘
```

## Why it exists

The client and server were starting to duplicate the same checks (action allowlists, error codes, manifest shapes). Drift between them produces bugs where the client preflight passes and the server rejects — the exact UX failure mode the preflight is meant to prevent. Sharing the policy in one TypeScript package means the two stay in lockstep by construction. The trust list, action allowlists, and structural rules are intentionally readable so anyone running the verifier can audit what RealReel considers a trusted capture.

## What's not here

Anything that requires I/O, crypto, or platform-specific bindings:

- **Cert chain validation** → server-side (c2pa-node does the math).
- **Hash-assertion verification** → server-side (same).
- **Cert revocation lookup** → server-side (DB).
- **Upload-time app attestation** (App Attest / Play Integrity) → server-side.
- **Manifest reading from bytes** → consumer-side (c2pa-ios / c2pa-android on the client, c2pa-node on the server).

This package starts from a parsed manifest store and applies the trust policy. Loading the manifest is the caller's job.

## Layout

- `src/shapes/`     — Typed shapes for the c2pa-rs JSON output.
- `src/errors/`     — `VerifyErrorCode` enum.
- `src/policies/`   — Pure functions over parsed manifest objects.
- `src/trust-list/` — Curated trusted-issuer entries (RealReel, Pixel, etc.).

## License

Apache-2.0.
