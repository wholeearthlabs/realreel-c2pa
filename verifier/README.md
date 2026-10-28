# RealReel C2PA Verifier

Cloud Run service that validates each upload's embedded C2PA manifest against a
curated trust list and revocation state. It's synchronous: the Supabase
`verify-and-create-media` edge function calls it before any `media` row is
inserted.

Self-contained, with its own `package.json`, `Dockerfile`, dependencies, and
tests. The architecture is in [`TRUST_ARCHITECTURE.md`](../TRUST_ARCHITECTURE.md);
deploying and running it in [`DEPLOY.md`](DEPLOY.md) and
[`OPERATIONS.md`](OPERATIONS.md).

## Layout

```
verifier/
├── Dockerfile                ← builds from the repo root (see Build + container)
├── trust-sources.yaml        ← curated trusted C2PA content sources + TSA pools
├── trust-sources/            ← the public PEMs each entry's `root_cert` points at
│                               (realreel/ also holds the ICA + both OCSP responder certs)
├── src/
│   ├── server.ts             ← Fastify entrypoint: auth, SSRF guard
│   ├── verify.ts             ← verify(): orchestrator-level gates, then the profile
│   ├── ports.ts              ← datastore port — pass your own `datastore` to verify()
│   ├── db.ts                 ← default Postgres adapter
│   ├── trust/                ← trust-sources loader + issuer → source dispatcher
│   ├── profiles/             ← realreel: two-stage manifest, revocation, Stage-2 attestation
│   ├── attestation/          ← Stage-2 App Attest (iOS) + Play Integrity (Android)
│   ├── cert-validity.ts      ← time-bound certificate-validity gates
│   ├── generative-ai.ts      ← generative-AI provenance gate
│   ├── location-privacy.ts   ← location-privacy backstop
│   ├── derive-metadata.ts    ← displayed metadata, derived from the verified bytes
│   ├── container-sniff.ts    ← byte-level photo / video container sniff
│   ├── sanitize.ts           ← strips re-verification-only data before persistence
│   ├── harness/              ← crJSON conformance harness (below)
│   └── errors.ts · config.ts · observability.ts
└── __tests__/
```

## Local development

```bash
make verifier-dev   # from the repo root
```

Runs the verifier against a local Postgres with the verifier schema applied, at
the default `DATABASE_URL`, with a placeholder shared secret and the SSRF host
config; it restarts on `src/` changes. For anything beyond the defaults, copy
`verifier/.env.example`.

Without Make, `npm run dev` (tsx watch) reads only `PORT` (default 8787) — set
the rest yourself. The minimum, mirroring `make verifier-dev`:

> **Local-dev values only.** Production uses Secret Manager-mounted, rotated
> credentials.

```
DATABASE_URL=postgres://postgres:postgres@127.0.0.1:54322/postgres
VERIFIER_SHARED_SECRET=dev-shared-secret-not-for-prod
ASSET_STORAGE_HOST_REGEX=^http://(127\.0\.0\.1|localhost):54321/storage/v1/object/sign/
ASSET_STORAGE_HOST_ALLOWLIST=127.0.0.1:54321,localhost:54321
```

SSRF is checked twice: `ASSET_STORAGE_HOST_REGEX` matches the URL's shape, and
`ASSET_STORAGE_HOST_ALLOWLIST` — comma-separated lowercase hosts compared against
`new URL(signedUrl).host` — is authoritative, so the userinfo-prefix trick
(`https://abc.supabase.co@attacker.com/...`) fails even under a permissive regex.

Stage-2 attestation (`PLAY_INTEGRITY_PACKAGE_NAME`,
`PLAY_INTEGRITY_CLOUD_PROJECT_NUMBER`, `ATTESTATION_REQUIRED`) and
`NETWORK_REVOCATION` stay unset locally: the verifier runs lenient (structural
envelope check + nonce burn, JWS decode skipped) and makes no OCSP request.
Production sets all four — see [DEPLOY.md](DEPLOY.md).

## Tests

```bash
npm test             # vitest run — or `make test-verifier` from the repo root
npm run test:watch
```

- **Git LFS required.** The binary fixtures in `__tests__/fixtures/` live in
  [Git LFS](https://git-lfs.com). Install it before cloning
  (`brew install git-lfs && git lfs install`), or run `git lfs pull` once;
  otherwise they arrive as small pointer files and the suite fails with
  decode/parse errors. New binaries dropped there are tracked automatically
  (the root `.gitattributes`).
- The crJSON harness suites need the pinned `c2patool` and `faketime` on `PATH`,
  and skip without them — see [`CRJSON_HARNESS.md`](CRJSON_HARNESS.md).

## Build + container

```bash
npm run build                                               # tsc → dist/
docker build -f verifier/Dockerfile -t realreel-verifier .  # from the repo root
```

The image builds from the **repo root** so the `@realreel/c2pa-trust-core`
workspace dependency compiles from source into it. Release images are built in
CI from a `verifier-v<semver>` tag — see [`RELEASING.md`](../RELEASING.md).

## Trust list

The trust list is the set of cameras whose C2PA captures the verifier will accept (see [`TRUST_ARCHITECTURE.md` § Multi-source trust](../TRUST_ARCHITECTURE.md#multi-source-trust) for the current sources and why).

The trust list is split across two files. The cross-process portion — `id`, `displayName`, `issuerMatch` substring, optional `commonNameMatch` discriminator, `rootCommonName` — lives in `@realreel/c2pa-trust-core`'s `TRUSTED_ISSUERS` array (at `trust-core/src/trust-list/trusted-issuers.ts`). The React Native client preflight gate reads from the same array, so the two validators cannot disagree on what counts as a trusted issuer.

`commonNameMatch` is optional and tightens an otherwise-loose `issuerMatch`. The current Pixel entry pins `issuerMatch: "Google LLC"` AND `commonNameMatch: "Pixel Camera"` so a future non-Pixel Google C2PA program (Workspace, Drive) cannot route through the Pixel entry. Entries without a `commonNameMatch` route on `issuerMatch` alone (e.g. RealReel, whose issuer name is already brand-specific enough).

`trust-sources.yaml` (in this directory) holds the verifier-only per-source policy, joined to TRUSTED_ISSUERS by `id` at startup:

- `id`: machine-readable slug — MUST match a TRUSTED_ISSUERS entry. The loader throws at startup if a YAML id has no shared-package match.
- `name`, `description`: human-readable.
- `root_cert`: relative path to the trust anchor's root PEM.
- `verification_profile`: `realreel` (eligible to sign Stage 2 / active manifest) or `wrap_parent_only` (trusted only as a Stage 1 parent inside a RealReel-wrapped upload).
- `revocation` (optional): `ocsp_hosts`, the source's OCSP responders as c2pa-rs host patterns (`scheme://[*.]host[:port]`, scheme required, port matched literally). The union of every source's hosts is the only set of hosts c2pa-rs may contact. RealReel sources declare none: their certificates are revoked through the issued-certificates ledger.

**Third-party parent revocation.** A wrapped capture from a `wrap_parent_only` source has no ledger row, so with `NETWORK_REVOCATION=true` (see [DEPLOY.md](DEPLOY.md)) c2pa-rs asks the responder that source declares for the parent's leaf-certificate OCSP status on every wrapped upload. A `revoked` answer rejects as `UNTRUSTED_ISSUER`; no answer — responder unreachable, blocked, timed out, or a response stapled into the manifest, which c2pa-rs never fetches past — rejects as retryable `VERIFIER_UNAVAILABLE` rather than passing. The asset is read offline first; the read with OCSP fetch on happens only for a wrap whose capture source declares responders, after every structural gate, so an uploaded store cannot drive requests before it has proved to be a valid wrap. Off (the default outside production), c2pa-rs makes no network request. c2pa-rs accepts an answer only from a responder whose certificate carries OCSP signing and chains to the anchor pool, though not specifically to the issuing CA. It also queries an issuing CA when the CA's own issuer is in the signer's `x5chain`; Pixel's chain stops at the issuing CA, so only the leaf is asked.

**One ingestion profile, force-wrap.** The verifier dispatches only the `realreel` profile when ingesting an active manifest (see `verify.ts` — anything else is rejected with `UNTRUSTED_ISSUER`). Every upload must therefore carry a RealReel-signed Stage 2 manifest. `wrap_parent_only` means the root sits in the c2pa-node trust bundle so parent-chain validation succeeds in wrap mode, but a raw single-stage upload chained to that root is rejected at the force-wrap gate.

**Generative-AI provenance, refused ahead of trust.** Before issuer resolution, `verify.ts` scans the active manifest and every manifest it references through an ingredient (any relationship, nested `related` sub-actions included) for an action whose IPTC `digitalSourceType` is `trainedAlgorithmicMedia` (a model produced the content) or `compositeWithTrainedAlgorithmicMedia` (a model changed it) and rejects a hit with `AI_GENERATED` (`src/generative-ai.ts`; the pure policy is `findGenerativeAiSource`, exported by `@realreel/c2pa-trust-core` from `trust-core/src/policies/generative-ai.ts`). Issuer-blind on purpose: the action allowlist admits `c2pa.created` on a capture and says nothing about what kind of creation it was, so a trusted camera signing model output is refused the same as a foreign generator, and the code names the content rather than the signer. Manifests the active one does not reference are ignored, so an appended stray manifest cannot relabel a genuine capture. Camera-pipeline terms (`computationalCapture`, `algorithmicallyEnhanced`) are not treated as AI.

Substring matching is for routing, **not** for trust: by the time the dispatcher uses `issuerMatch`, c2pa-node has already validated the manifest's cert chain against `trust_anchors`.

**Onboarding a new camera vendor** — declarative, no verifier code change:

1. Register the entry in `trust-core/src/trust-list/trusted-issuers.ts` with the cross-process metadata.
2. Append a `trust-sources.yaml` entry here with the matching `id` and verifier-specific policy.
3. Commit the PEM file at `trust-sources/<id>/root.pem`.
4. Read the OCSP responder host off a sample capture's leaf certificate — its AIA `OCSP` URI (`c2patool <sample> --certs`, then `openssl x509 -noout -ext authorityInfoAccess`) — and declare it as `revocation.ocsp_hosts`. Without the block the source gets no network revocation check.
5. Ensure a verification profile handler exists.
6. Redeploy.

**To remove a vendor:** delete the entry from both files + the PEM directory; redeploy.

## Conformance test harness (crJSON)

`src/harness/` emits [crJSON](https://spec.c2pa.org/specifications/specifications/2.4/crJSON/crjson-format.html) for an asset validated against supplied C2PA and TSA trust lists at a supplied instant — the harness the C2PA Conformance Program requires. It's a callable function with a thin CLI:

```bash
npm run crjson --workspace verifier -- \
  --asset input.jpg --trust-list C2PA-TRUST-LIST.pem --tsa-trust-list C2PA-TSA-TRUST-LIST.pem \
  --validation-time 2026-08-17T00:00:00Z --out input.crjson --record input.run.json
```

`__tests__/harness/` uses it as a test harness too: every fixture's crJSON is schema-validated and pinned as a golden across trust-list and validation-time variations.

It needs `c2patool` and `libfaketime` on PATH, or the `crjson-harness` Docker target, which needs neither. See [`CRJSON_HARNESS.md`](CRJSON_HARNESS.md) for the design, version pins, and c2patool's known crJSON deviations.
