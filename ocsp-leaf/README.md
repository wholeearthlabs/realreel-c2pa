# realreel-ocsp-leaf — leaf-status OCSP responder

Dynamic RFC 6960 responder for **RealReel leaf certificates** (per-device
claim-signing certs issued by the Claim Signing ICA). The sibling of the
pre-signed ICA-status Worker in `../ocsp/`:

| | ICA status (`../ocsp/`) | Leaf status (this service) |
|---|---|---|
| Cardinality | one cert | one serial per enrolled device key |
| Status source | sticky KV value, daily refresh | `issued_certificates` ledger, live |
| Signing | pre-signed daily (KMS `realreel-ocsp-root`) | per request (KMS `realreel-ocsp-ica`) |
| Runtime | Cloudflare Worker | Cloud Run (Deno) |
| Responder cert | root-signed `realreel-ocsp-responder-1.pem` | ICA-signed `realreel-leaf-ocsp-responder-1.pem` |

RFC 6960 §4.2.2.2: a delegated responder must be certified by the CA that
issued the certificate in question — hence the ICA-signed responder cert.

## Status semantics

Read from `public.lookup_signing_key_revocation(serial)` over the app-side
`issued_certificates` ledger (survives account deletion; system of record):

- row, `revoked_at IS NULL` → **good** (signed)
- row, `revoked_at` set → **revoked** (signed; revocationTime = `revoked_at`;
  the ledger's free-text `revoked_reason` is not a CRLReason and is omitted)
- no row → unsigned **unauthorized** (RFC 5019 §2.2.3). Every genuinely
  issued leaf has a ledger row before the cert leaves the CA, so real leaves
  always get a signed answer — and enumerating random serials against this
  public endpoint costs a cheap indexed lookup, never a KMS signature.

Superseded and expired leaves answer **good**: supersession is app-fleet
state, and expiry is judged from the certificate itself by relying parties.

`thisUpdate → nextUpdate` is short (`OCSP_LEAF_VALIDITY_HOURS`, default 24,
max 72) so a revocation propagates through caches well inside the CP §3.6
72-hour clock. Successful responses are served with `max-age=300`; the
unsigned error forms are `no-store`.

## How requests reach it

New-hierarchy leaves carry `AIA id-ad-ocsp = http://ocsp.realreel.xyz` — the
same host as the ICA-status Worker. The Worker stays the public front door:
it answers ICA CertIDs from KV as today and relays **single-CertID requests
whose issuer hashes name the ICA** (i.e. RealReel leaves) to this service —
never arbitrary third-party CertIDs. The relay activates when
`LEAF_RESPONDER_ORIGIN` is set in the Worker's `wrangler.toml` (the cutover
deploy); until then the service is reachable directly at its Cloud Run URL.

## Endpoints

- `POST /` — DER `OCSPRequest` body (≤ 8 KiB)
- `GET /{url-encoded base64 request}` — RFC 6960 A.1 form
- `GET /healthz` — liveness; `GET /healthz/ready` — DB round-trip probe

Single-CertID requests only (multi-request → `unauthorized`, matching the
Worker). CertIDs whose issuer hashes aren't the ICA's → `unauthorized`
without a ledger lookup or a KMS signature spent.

## Deploy (Cloud Run)

Build from the **repo root** (the image needs `../ocsp/ocsp.ts`,
`../ca/_shared/kms.ts`, and the trust-source PEMs):

```sh
docker build -f ocsp-leaf/Dockerfile -t <region>-docker.pkg.dev/<project>/realreel/ocsp-leaf .
docker push <region>-docker.pkg.dev/<project>/realreel/ocsp-leaf
gcloud run deploy realreel-ocsp-leaf \
  --image <…>/ocsp-leaf --region <region> --project <project> \
  --service-account <ocsp-leaf-sa> \
  --set-env-vars GCP_KMS_KEY_RESOURCE=<leaf-ocsp-signing-key-version-resource> \
  --set-secrets DATABASE_URL=<readonly-url-secret>:latest \
  --allow-unauthenticated
```

Service-account needs:
- `roles/cloudkms.signer` on the leaf-OCSP signing key **only**.
- A read-only `DATABASE_URL` whose Postgres role has EXECUTE on
  `lookup_signing_key_revocation` (the same role the verifier uses).

Auth: on Cloud Run the KMS call uses the ambient service-account identity
(metadata server). Locally, set `GCP_KMS_SA_JSON` and it signs exactly like
the CA edge functions do.

## Local dev

```sh
cd ocsp-leaf
deno task test                 # pure-core tests (ephemeral signer)
DATABASE_URL=… GCP_KMS_KEY_RESOURCE=… GCP_KMS_SA_JSON=… deno task start
# then:
openssl ocsp -issuer ../verifier/trust-sources/realreel/realreel-claim-signing-ca.pem \
  -serial 0x<hex> -url http://localhost:8080 -resp_text -no_nonce \
  -VAfile ../verifier/trust-sources/realreel/realreel-leaf-ocsp-responder-1.pem
```

## Ops

- Revocation flow: revoke on `user_signing_keys` per the app repo's
  `docs/runbooks/revoke-signing-key.md`; the ledger trigger mirrors it and
  this responder reflects it within the cache window — nothing to do here.
- Responder cert re-issue (annually — the weekly trust-anchor audit WARNs
  60 days out): mint via `ca/tools/build-ca-certs.ts ocsp-leaf`, commit
  the PEM, redeploy this service (the PEM is baked into the image).
