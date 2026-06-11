# RealReel C2PA — open signing & verification

The cryptography, signing, and verification behind [RealReel](https://realreel.xyz)'s
authenticity guarantee.

RealReel is a photo-sharing app where only **genuine, unedited photos captured in
the app** can be uploaded. That guarantee rests on a hardware-bound,
[C2PA](https://c2pa.org/)-based signing and verification pipeline. The app itself
is closed-source; **this** — how a capture is signed on-device and how it's
verified server-side — is the part we want anyone to be able to read, audit, and
learn from.

> [!WARNING]
> **Not yet independently audited.** This code is published for transparency and
> community review and has not undergone a formal third-party security audit.
> Use at your own risk, and please report anything you find — see
> [`SECURITY.md`](./SECURITY.md).

## How it works

Every RealReel photo carries a **two-stage C2PA manifest** signed by a per-user
key that lives in the device's secure hardware (Apple Secure Enclave / Android
StrongBox or TEE):

1. **Enrollment (once per device).** The device proves it holds a genuine
   hardware key via platform attestation (iOS App Attest / Android Key
   Attestation), and the RealReel CA issues it a short-lived leaf certificate.
2. **Capture — Stage 1.** The in-app camera signs the captured frame with the
   enrolled hardware key.
3. **Upload — Stage 2.** The app signs an upload manifest that references Stage 1
   as a `parentOf` ingredient and declares the upload-time transforms (resize,
   rotate, transcode), plus a fresh platform-attestation envelope.
4. **Verification.** A server-side verifier chain-validates both stages against
   the RealReel CA root, checks revocation, enforces an action allowlist, and
   validates the Stage-2 attestation before any media is accepted.

Most phones don't yet produce C2PA-signed photos, so RealReel ships its own in-app
C2PA camera — but the trust model is extensible by **root certificate** (today:
**RealReel** and **Google Pixel**). See
[`TRUST_ARCHITECTURE.md` § Multi-source trust](./TRUST_ARCHITECTURE.md#multi-source-trust)
for how, alongside what it defends against and where the guarantee is bounded.

## Workspaces

| Workspace                      | What it is                                                                                  | Runtime          |
| ------------------------------ | ------------------------------------------------------------------------------------------- | ---------------- |
| [`trust-core/`](./trust-core)  | Shared trust list, action policies, and C2PA manifest shapes (consumed by app + verifier).  | TypeScript       |
| [`verifier/`](./verifier)      | The C2PA verification microservice (chain validation, revocation, attestation, TSA checks). | TypeScript/Node  |
| [`native/`](./native)          | Hardware-backed capture-signing module (iOS Swift / Android Kotlin + a TS bridge).          | Swift / Kotlin   |
| [`ca/`](./ca)                  | Enrollment / certificate-authority and challenge edge functions.                            | TypeScript/Deno  |

The CA signing key itself is **not** in this repository — it lives in a hardware
security module. Only the public RealReel root certificate ships here, alongside
the public trust anchors the verifier needs (see [`NOTICE`](./NOTICE)).

**On npm:** `trust-core/` and `native/` publish as
[`@realreel/c2pa-trust-core`](https://www.npmjs.com/package/@realreel/c2pa-trust-core)
and [`@realreel/photo-attest`](https://www.npmjs.com/package/@realreel/photo-attest)
— an integrating app typically installs **both** (trust-core describes and gates
captures; photo-attest produces them). `verifier/` and `ca/` deploy from source,
not npm.

Thinking of reusing part of this in your own app? See [`ADAPTING.md`](./ADAPTING.md)
— what's reusable, what's RealReel-specific, and the exact swap-points.

## Quickstart

**Prerequisites:** [Node.js](https://nodejs.org) ≥ 22, [Deno](https://deno.com) ≥ 2
(for the `ca` workspace), and [git-lfs](https://git-lfs.com) (the verifier's
binary test fixtures are stored in Git LFS — install it **before** cloning, or run
`git lfs pull` after).

```bash
npm install          # installs + links the npm workspaces
npm test             # runs every suite (see below)
```

`npm test` runs, in order:

- **trust-core** — `vitest`
- **verifier** — `tsc` (src typecheck) + `vitest`
- **ca** — `deno test`

Per workspace:

```bash
npm run test:trust-core
npm run test:verifier
npm run test:ca                  # requires Deno
( cd native && npx tsc --noEmit ) # typechecks the TS bridge
```

### Building the native module

The `native/` workspace's TypeScript bridge typechecks here, but the Swift and
Kotlin sources need a full Expo / Xcode / Gradle toolchain (with autolinking) to
compile — they're included for transparency and review, not standalone build.

## Contributing & security

- Contributions welcome under [Apache-2.0](./LICENSE) — see
  [`CONTRIBUTING.md`](./CONTRIBUTING.md).
- Releasing any package or service — see [`RELEASING.md`](./RELEASING.md).
- Report vulnerabilities privately — see [`SECURITY.md`](./SECURITY.md).

## License

[Apache License 2.0](./LICENSE) © Whole Earth Labs LLC. See [`NOTICE`](./NOTICE)
for third-party attributions.
