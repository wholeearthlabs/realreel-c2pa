# RealReel C2PA Verifier

Cloud Run microservice that validates the embedded C2PA manifest of each upload against a curated trust list and revocation state. Synchronous; called from the Supabase `verify-and-create-media` edge function before any `media` row is inserted.

This directory is **self-contained**: own `package.json`, own `Dockerfile`, own dependencies, own tests.

For the architectural context, see [`TRUST_ARCHITECTURE.md`](../TRUST_ARCHITECTURE.md).

## Layout

```
verifier/
├── package.json
├── tsconfig.json
├── Dockerfile
├── trust-sources.yaml          ← curated list of trusted C2PA content sources
├── trust-sources/
│   ├── realreel/root.pem       ← the RealReel CA root certificate
│   └── pixel/root.pem          ← Google Content Credentials root (Pixel Camera)
├── src/
│   ├── server.ts               ← Fastify entrypoint + auth + SSRF guard
│   ├── verify.ts               ← main verify() — dispatches to a profile
│   ├── trust/
│   │   ├── loader.ts           ← parses YAML, reads PEMs, builds trust_anchors bundle
│   │   ├── dispatcher.ts       ← issuer → source_id resolver
│   │   └── types.ts
│   ├── profiles/
│   │   └── realreel.ts         ← 2-stage manifest + revocation denylist + Stage-2 attestation
│   ├── attestation/
│   │   ├── apple.ts            ← Stage-2 App Attest validator (iOS): structural + ECDSA chain against enrollment-stored credCert pubkey + single-use nonce burn
│   │   ├── pki-node.ts         ← node:crypto primitives (sha256, P-256 raw pubkey import, ECDSA verify)
│   │   └── play_integrity.ts   ← Stage-2 Play Integrity validator (Android): plausibility filter + Google decodeIntegrityToken + STRONG verdict enforcement
│   ├── db.ts                   ← postgres client; single call site
│   ├── sanitize.ts             ← strips signature bytes + cert chain from manifest
│   ├── errors.ts               ← VerifyErrorCode + VerifyError
│   ├── config.ts               ← env var parsing
│   └── observability.ts        ← Sentry init + pino logger
└── __tests__/
    └── ...
```

## Local development

There's no app to run here — just the verifier service. Run it locally as a standalone HTTP service against a local Postgres that has the verifier schema applied.

### Run the verifier locally

```bash
make verifier-dev   # from repo root
```

Runs just the verifier with a local-dev env wired up (a local Postgres reachable at the default `DATABASE_URL`, a placeholder shared secret, and the SSRF host config). The verifier auto-restarts on `src/` changes. For anything beyond the defaults, copy `verifier/.env.example` and supply your own values.

### Bare-bones (no Make)

```bash
cd verifier
npm install
npm run dev     # tsx watch — auto-reloads on src/ changes
```

`npm run dev` itself reads only `PORT` (default 8787) — every other env var must be set externally. The `make verifier-dev` target is the canonical source for those values; here's the minimum set if you're invoking `npm run dev` directly:

> **Local-dev values only.** Do not use these placeholder values in production; the production deployment uses Secret Manager-mounted secrets with rotated credentials.

```
DATABASE_URL=postgresql://postgres:postgres@127.0.0.1:54322/postgres
VERIFIER_SHARED_SECRET=dev-shared-secret-not-for-prod
ASSET_STORAGE_HOST_REGEX=^https?:\/\/127\.0\.0\.1:54321\/storage\/v1\/object\/sign\/
ASSET_STORAGE_HOST_ALLOWLIST=127.0.0.1:54321
```

`ASSET_STORAGE_HOST_REGEX` is the first SSRF layer (URL shape match); `ASSET_STORAGE_HOST_ALLOWLIST` is the authoritative second layer — comma-separated lowercase hosts compared against `new URL(signedUrl).host`. The two-step defense neutralizes the userinfo-prefix trick (`https://abc.supabase.co@attacker.com/...`) even if the regex is permissive.

Stage-2 attestation env (`PLAY_INTEGRITY_PACKAGE_NAME`, `PLAY_INTEGRITY_CLOUD_PROJECT_NUMBER`, `ATTESTATION_REQUIRED`) is intentionally left unset locally — the verifier runs in lenient mode (structural envelope check + nonce burn, JWS decode skipped). Production sets all three; see [DEPLOY.md](DEPLOY.md).

## Running tests

```bash
npm test                # vitest run
npm run test:watch      # vitest watch
```

Or from repo root:

```bash
make test-verifier
```

> **Git LFS required.** The binary test fixtures in `__tests__/fixtures/` (`.jpg`, `.png`, `.mov`, …) are stored in [Git LFS](https://git-lfs.com). Install it **before** cloning (`brew install git-lfs && git lfs install`); on an existing clone run `git lfs pull` once. Without it the fixtures arrive as small text pointer files and the suite fails with decode/parse errors. New binary fixtures dropped into that directory are tracked automatically (the patterns live in the repo-root `.gitattributes`).

## Build + container

```bash
npm run build           # tsc → dist/ (local)
```

The container image builds from the **repo root** (not `verifier/`), so the
`@realreel/c2pa-trust-core` workspace dep is compiled from source into it:

```bash
# from the repo root:
docker build -f verifier/Dockerfile -t realreel-verifier .
```

## Trust list

The trust list is the set of cameras whose C2PA captures the verifier will accept — today RealReel's own in-app camera and Google Pixel (see [`TRUST_ARCHITECTURE.md` § Multi-source trust](../TRUST_ARCHITECTURE.md#multi-source-trust) for why). It's designed to grow: onboarding a new camera is a small, declarative change (a root PEM plus two metadata entries), not a verifier code change.

The trust list is split across two files. The cross-process portion — `id`, `displayName`, `issuerMatch` substring, optional `commonNameMatch` discriminator, `rootCommonName` — lives in `@realreel/c2pa-trust-core`'s `TRUSTED_ISSUERS` array (at `trust-core/src/trust-list/trusted-issuers.ts`). The React Native client preflight gate reads from the same array, so the two validators cannot disagree on what counts as a trusted issuer.

`commonNameMatch` is optional and tightens an otherwise-loose `issuerMatch`. The current Pixel entry pins `issuerMatch: "Google LLC"` AND `commonNameMatch: "Pixel Camera"` so a future non-Pixel Google C2PA program (Workspace, Drive) cannot route through the Pixel entry. Entries without a `commonNameMatch` route on `issuerMatch` alone (e.g. RealReel, whose issuer name is already brand-specific enough).

`trust-sources.yaml` (in this directory) holds the verifier-only per-source policy, joined to TRUSTED_ISSUERS by `id` at startup:

- `id`: machine-readable slug — MUST match a TRUSTED_ISSUERS entry. The loader throws at startup if a YAML id has no shared-package match.
- `name`, `description`: human-readable.
- `root_cert`: relative path to the trust anchor's root PEM.
- `verification_profile`: `realreel` (eligible to sign Stage 2 / active manifest) or `wrap_parent_only` (trusted only as a Stage 1 parent inside a RealReel-wrapped upload).

**One ingestion profile, force-wrap.** The verifier dispatches only the `realreel` profile when ingesting an active manifest (see `verify.ts` — anything else is rejected with `UNTRUSTED_ISSUER`). Every upload must therefore carry a RealReel-signed Stage 2 manifest. `wrap_parent_only` (today: Pixel) means the root sits in the c2pa-node trust bundle so parent-chain validation succeeds in wrap mode, but a raw single-stage upload chained to that root is rejected at the force-wrap gate.

Substring-match-vs-trust note: by the time the dispatcher uses `issuerMatch`, the manifest's cert chain has already been validated against `trust_anchors` (chain validation by c2pa-node). Substring matching is for routing, NOT for trust.

**Onboarding a new camera vendor (two-file edit):**

1. Register the entry in `trust-core/src/trust-list/trusted-issuers.ts` with the cross-process metadata.
2. Append a `trust-sources.yaml` entry here with the matching `id` and verifier-specific policy.
3. Commit the PEM file at `trust-sources/<id>/root.pem`.
4. Ensure a verification profile handler exists.
5. Redeploy.

**To remove a vendor:** delete the entry from both files + the PEM directory; redeploy.
