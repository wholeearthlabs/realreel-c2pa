# crJSON conformance harness

`src/harness/` validates an asset against a supplied C2PA Trust List and TSA Trust List at a supplied RFC 3339 instant, and emits [crJSON](https://spec.c2pa.org/specifications/specifications/2.4/crJSON/crjson-format.html). The C2PA Conformance Program (v0.2) requires this of a Generator Product with validation functionality. It is a callable function — `runCrjsonHarness` — with a thin CLI over it.

## Running it

```bash
npm run crjson --workspace verifier -- \
  --asset input.jpg --trust-list C2PA-TRUST-LIST.pem --tsa-trust-list C2PA-TSA-TRUST-LIST.pem \
  --validation-time 2026-08-17T00:00:00Z --out input.crjson --record input.run.json
```

Or the pinned image, which needs neither c2patool nor libfaketime installed:

```bash
docker build -f verifier/Dockerfile --target crjson-harness -t crjson-harness .   # from the repo root
docker run --rm --user "$(id -u):$(id -g)" -v "$PWD:/work" -w /work crjson-harness --asset input.jpg …
```

`--validation-time` must carry an explicit offset (`Z` or `±hh:mm`). `--out` receives the crJSON exactly as the validator emitted it; `--record` (else stderr) receives the run record: validator and engine versions, SHA-256 of every input, the instant, and whether the engine agreed.

| Exit | Meaning |
|---|---|
| 0 | crJSON written; the engine agreed with it |
| 2 | usage error or unreadable input |
| 3 | c2patool or faketime missing |
| 4 | the validator failed on the asset — there is no crJSON |
| 5 | crJSON written, but the engine disagreed with it or failed on the asset (the record says which) |

## What produces the crJSON, and the cross-check

RealReel's validation functionality is c2pa-rs: `verify.ts` embeds it through `@contentauth/c2pa-node` and layers ingestion policy on top (issuer and action allowlists, upload attestation, revocation). That policy layer emits RealReel error codes rather than C2PA status codes, so it has no crJSON representation — everything crJSON reports is c2pa-rs's verdict.

c2pa-node exposes neither c2pa-rs's crJSON serializer nor a validation-time override, so each run does two things and reconciles them:

- **c2patool** produces the crJSON, fed the same settings document `verify.ts` builds (`buildVerifierSettings` with the supplied anchors — shared code, not a reimplementation).
- **The verifier's own engine** (`engine-probe.ts`) validates the same asset with the same settings at the same instant, and its validation results are compared status by status against the crJSON's. A difference is a failed run (exit 5), not a footnote.

c2pa-rs keeps one anchor pool for claim-signing and TSA certificates, so the two supplied lists are concatenated into it. A root on the TSA list is therefore an acceptable claim-signing anchor to the engine — Google's C2PA root is on the official TSA list — and scoping each anchor's role stays the policy layer's job (`trust/types.ts`).

## Validation time

c2pa-rs reads the system clock with no override, so both children run under libfaketime with the clock *frozen* at the requested instant, which also makes the output byte-deterministic. Install with `brew install libfaketime` or `apt-get install faketime`.

On macOS, faketime cannot reach SIP-protected system binaries. The harness invokes c2patool and `node` (`process.execPath`) directly so this doesn't affect it, but don't expect `faketime … date` to work there when checking your install.

## Tests

`__tests__/harness/crjson-harness.test.ts` proves the harness itself: each input reaches the validator, the output validates against `crjson-2.4.schema.json` (verbatim from spec 2.4 §5), runs are deterministic, and the engine agrees on every fixture.

`crjson-goldens.test.ts` then *uses* it — committed `.crjson` goldens per fixture × (trust lists, instant), covering leaf expiry at a future instant, TSA-anchored validity, trust-list steering, a wrap-mode parent, and an offline drain chain. `UPDATE_CRJSON_GOLDENS=1` regenerates them; read the diff.

Both suites skip when the tools are missing locally, and are mandatory in CI (`CRJSON_HARNESS_REQUIRED=1`).

## Version pins

The harness's validator and the verifier's engine must stay on the same c2pa-rs minor. The c2patool version and its tarball checksum are pinned identically in `.github/workflows/ci.yml` and the Dockerfile's `crjson-harness` stage, and recorded here as part of the submitted evidence:

| Component | Version | c2pa-rs |
|---|---|---|
| `@contentauth/c2pa-node` (this verifier's engine) | 0.8.3 | 0.90.5 |
| `c2patool` (harness crJSON serializer) | 0.27.15 | 0.90.15 |
| `c2pa-ios` / `c2pa-android` (device gate + signer) | 0.0.9 | 0.79.5 |

## Known crJSON deviations of c2patool 0.27.15

None of these touch the status codes:

- `redacted_assertions` is omitted from a v2 claim when empty (spec §3.5.1 wants `[]`; fixed on c2pa-rs main).
- Serialization fails outright on an ingredient assertion that breaks the CDDL co-presence rule (spec §3.6.1 wants `{}` for that assertion).
- The `c2pa.time-stamp` DER token is emitted as an integer array rather than a `b64'` string (spec §3.6.3 Table 1 — visible in the `realreel-drained@baseline` golden).

Inside `validationResults`, c2pa-rs stamps `specVersion: "2.3.0"` — a constant in its crJSON serializer (`CRJSON_SPEC_VERSION`, unchanged on main), i.e. the validator's own statement of the spec it validates against. The harness does not rewrite it; a test pins it so a change is noticed.
