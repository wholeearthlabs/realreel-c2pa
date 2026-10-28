# Examples

## `verify-demo.ts` — verify a real photo end-to-end

Runs the real verifier pipeline against a bundled RealReel-signed sample and
prints the trust verdict, both stages, and the declared actions. It's the
runnable twin of `verifier/__tests__/verify-realreel.test.ts`.

```bash
npm install    # once, from the repo root
npm run demo   # or: cd verifier && npx tsx ../examples/verify-demo.ts
```

```
RealReel C2PA — verify demo
sample: .../verifier/__tests__/fixtures/realreel-uploaded.jpg

  ✓ TRUSTED  — manifest chains to the RealReel CA and passed every gate
  trust source: realreel-legacy

Two-stage provenance
  Stage 1 (capture): realreel-20260820-145453.jpg
    issuer: RealReel
    signed: 2026-08-20T21:54:53+00:00
    capturer: fc7ce1d3-82a8-4119-8e98-fe9b2161df6a
  Stage 2 (upload):  realreel-20260821-114817.jpg
    issuer: RealReel
    signed: 2026-08-21T18:48:19+00:00

Declared actions
  Stage 1: c2pa.created
  Stage 2: c2pa.opened, c2pa.orientation, c2pa.resized.proportional, c2pa.transcoded, c2pa.edited.metadata, c2pa.redacted
```

It exits `0` on a Trusted verdict and `1` on a rejection.

### Real vs. stubbed

The **real** `verify()` orchestrator runs: c2pa-node parses the manifest and
chain-validates it against the roots in `verifier/trust-sources.yaml`, the
`realreel` profile enforces the two-stage structure, revocation, and the action
allowlist, and the output is sanitized exactly as the service returns it.

Two things are stubbed so it needs **no external services**:

- **In-memory datastore** — a `VerifierDatastore` (`verifier/src/ports.ts`) in
  place of Postgres. The lookup returns the sample's enrolled, non-revoked key;
  the nonce burn and health check are no-ops.
- **Lenient attestation** — no Play Integrity config and `attestationRequired`
  left `false`, so no Google API call. Production enforces Stage-2 attestation
  (see `verifier/DEPLOY.md`).

### The sample

`verifier/__tests__/fixtures/realreel-uploaded.jpg` is a real RealReel-signed
JPEG: a Pixel 10 capture (Stage 1) re-signed at upload (Stage 2), chained to the
pre-conformance RealReel root (hence `realreel-legacy`), with a DigiCert RFC 3161
timestamp on both stages.

It's stored in [Git LFS](https://git-lfs.com). If the demo can't parse it, the
file probably arrived as a small text pointer — run `git lfs pull` once.
