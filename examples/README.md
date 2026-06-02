# Examples

## `verify-demo.ts` — CLI verify demo

A small, dependency-light demo that runs the verifier end-to-end against a
bundled sample C2PA file and prints a friendly trust verdict (Trusted or not,
the two stages, and the declared actions).

It's the runnable twin of `verifier/__tests__/verify-realreel.test.ts`: same
`verify()` pipeline, same sample, but turned into a script you can run.

### Run

From the repo root:

```bash
npm install        # once, installs workspace deps (incl. the verifier's)
npm run demo
```

Or directly:

```bash
cd verifier && npx tsx ../examples/verify-demo.ts
```

Expected output:

```
RealReel C2PA — verify demo
sample: .../verifier/__tests__/fixtures/realreel-uploaded.jpg

  ✓ TRUSTED  — manifest chains to the RealReel CA and passed every gate
  trust source: realreel

Two-stage provenance
  Stage 1 (capture): realreel-20260528-124629.jpg
    issuer: RealReel
    signed: 2026-05-28T19:46:30+00:00
    capturer: a73f9e58-7323-4fd6-970e-59fb0b4d2ea4
  Stage 2 (upload):  realreel-20260528-124641.jpg
    issuer: RealReel
    signed: 2026-05-28T19:46:41+00:00

Declared actions
  Stage 1: c2pa.created
  Stage 2: c2pa.opened, c2pa.resized, c2pa.transcoded, c2pa.redacted
```

The process exits `0` on a Trusted verdict and `1` on a rejection.

### What it does (and what it fakes)

It runs the **real** `verify()` orchestrator: c2pa-node parses the embedded
manifest and chain-validates it against the RealReel CA root in
`verifier/trust-sources/realreel/root.pem`, then the `realreel` profile enforces
the two-stage structure, the revocation denylist, and the action allowlist. The
output is sanitized exactly as the Cloud Run service would return it.

Two things are stubbed so it runs with **no external services**:

- **In-memory datastore.** The demo injects its own `VerifierDatastore` (the
  port defined in `verifier/src/ports.ts`) instead of the Postgres-backed one.
  The revocation lookup returns the sample's pre-registered (non-revoked)
  enrollment row, and the attestation nonce-burn + health-check are no-ops — so
  there's **no database**.
- **Lenient attestation mode.** No Play Integrity config is passed and
  `attestationRequired` is left `false`, so the demo makes **no Google Play
  Integrity API call**. (In production, Stage-2 attestation is enforced; see
  `verifier/DEPLOY.md`.)

### The sample

`verifier/__tests__/fixtures/realreel-uploaded.jpg` is a real RealReel-signed
JPEG: a Pixel 10 capture (Stage 1) re-signed at upload (Stage 2), trust-rooted
at the RealReel CA, with both stages carrying a DigiCert RFC-3161 timestamp.

The fixtures are stored in [Git LFS](https://git-lfs.com). If the demo fails to
parse the sample, the file probably arrived as a small text pointer — run
`git lfs pull` once.
