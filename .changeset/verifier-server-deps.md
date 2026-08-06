---
'@realreel/verifier': patch
---

Update the verifier's server-side dependencies: `@sentry/node` 8.55.2 → 10.69.0, `google-auth-library` 9.15.1 → 11.0.0, and `pino` 9.14.0 → 10.3.1.

`google-auth-library` v11's only breaking change is raising the floor to Node >= 22, and the image is `node:24-bookworm-slim`. The surface this service uses — `new GoogleAuth({ scopes })` and `getAccessToken(): Promise<string | null | undefined>` — is unchanged from v9, so Play Integrity token decoding is untouched. The v10 churn (the `Request`/`Transporter` overhaul) doesn't reach either call. Worth noting for the deploy: the transitive `gcp-metadata` moves 6.1.1 → 8.1.2, which is the Application Default Credentials path against Cloud Run's metadata server — the one code path the suite mocks rather than exercises. It fails closed (`VERIFIER_UNAVAILABLE`, retryable), never into an attestation bypass.

`pino` 10 keeps the same default JSON shape (`level`/`time`/`pid`/`hostname`/`msg`), so Cloud Logging field extraction is unaffected. Fastify 5.11 already declares `pino ^9.14.0 || ^10.1.0`, so the bump stays deduped to a single copy.

`@sentry/node` 10 shrinks rather than grows the image: `@sentry` + `@opentelemetry` together drop from ~68 MB to ~51 MB. `init()` and `captureMessage()` keep their v8 signatures, and both still work from ESM without an `--import` loader — which is how `observability.ts` and the trust loader call them.

`pino-pretty` 11 → 13 lands alongside this but carries no changeset: it is a dev dependency, and the runtime image installs with `--omit=dev`.
