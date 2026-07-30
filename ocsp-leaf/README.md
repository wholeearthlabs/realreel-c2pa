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
`LEAF_RESPONDER_ORIGIN` is set in the Worker's `wrangler.toml`.

That relay hop carries a shared secret (`LEAF_RELAY_SECRET`, header
`x-realreel-relay-secret`), and this service answers `403` without it. The AIA
URL is the Worker, so the Worker is the OCSP repository RFC 6960 and CP §4.11
describe and this service is only its backend — no OCSP client resolves it, so
the secret costs no conformance claim. What it buys: the open internet can no
longer spend a KMS signature per request. A missing or wrong secret makes the
Worker answer `internalError`, never a wrong status.

## Endpoints

- `POST /` — DER `OCSPRequest` body (≤ 8 KiB)
- `GET /{url-encoded base64 request}` — RFC 6960 A.1 form
- `GET /healthz` — liveness; `GET /healthz/ready` — DB round-trip probe.
  Point external uptime checks at `/healthz/ready`: on Cloud Run the frontend
  was observed answering exactly `/healthz` itself with a 404, while
  `/healthz/` and every other path reach the container. Container-side
  startup/liveness probes are unaffected.

The two probes are the only unauthenticated paths: gating them would put the
secret in the revision spec via the probe's `httpGet.httpHeaders`, readable by
any `run.viewer`. They reveal liveness and DB reachability only, but
`/healthz/ready` is a round-trip against a `max: 4` pool — the one path an
anonymous flood can still make this service spend on. To close it, point the
startup probe at `/healthz` and gate `/healthz/ready` with the rest.

Single-CertID requests only (multi-request → `unauthorized`, matching the
Worker). CertIDs whose issuer hashes aren't the ICA's → `unauthorized`
without a ledger lookup or a KMS signature spent.

## Deploy (Cloud Run)

Images are built in CI, never locally: this service signs with the CA
hierarchy's delegated OCSP key, so the deployed bytes must be traceable to a
commit. Tagging `ocsp-leaf-v<semver>` (matching `deno.json`'s `version`) runs
[`publish-ocsp-leaf-image.yml`](../.github/workflows/publish-ocsp-leaf-image.yml),
which pushes `ghcr.io/wholeearthlabs/realreel-ocsp-leaf:<semver>` with SLSA
build provenance.

```sh
git tag ocsp-leaf-v0.1.0 && git push origin ocsp-leaf-v0.1.0
make deploy-ocsp-leaf TAG=ocsp-leaf-v0.1.0   # config: ocsp-leaf/deploy.env
```

`make deploy-ocsp-leaf` verifies that provenance, copies GHCR → Artifact
Registry by digest, and deploys — image-only: env, secrets, the service
account, and the invoker-check setting below all carry over untouched
(confirmed by deploying with none of them passed). Anyone can check the same
image (make the GHCR package public first — a newly published package starts
private):

```sh
gh attestation verify oci://ghcr.io/wholeearthlabs/realreel-ocsp-leaf:<semver> \
  --repo wholeearthlabs/realreel-c2pa
```

The **first** deploy can't go through `make deploy-ocsp-leaf`: an image-only
deploy would create the service with no `DATABASE_URL` / `GCP_KMS_KEY_RESOURCE`,
and `main.ts` refuses to start without them. Copy the attested image across by
digest yourself, then deploy it with the configuration every later image-only
deploy preserves:

```sh
digest=$(docker buildx imagetools inspect \
  ghcr.io/wholeearthlabs/realreel-ocsp-leaf:<semver> --format '{{.Manifest.Digest}}')
docker buildx imagetools create \
  --tag <region>-docker.pkg.dev/<ca-project>/<repo>/ocsp-leaf:<semver> \
  "ghcr.io/wholeearthlabs/realreel-ocsp-leaf@${digest}"

gcloud run deploy realreel-ocsp-leaf \
  --image <region>-docker.pkg.dev/<ca-project>/<repo>/ocsp-leaf:<semver> \
  --region <region> --project <ca-project> \
  --service-account <ocsp-leaf-sa> \
  --set-env-vars GCP_KMS_KEY_RESOURCE=<leaf-ocsp-signing-key-version-resource> \
  --set-secrets DATABASE_URL=<readonly-url-secret>:latest,LEAF_RELAY_SECRET=<relay-secret>:latest \
  --startup-probe=httpGet.path=/healthz/ready,httpGet.port=8080,failureThreshold=6,periodSeconds=5,timeoutSeconds=4 \
  --no-invoker-iam-check
```

Not `--allow-unauthenticated`: that grants `roles/run.invoker` to `allUsers`,
which a domain-restricted-sharing constraint will reject. Disabling the invoker
check makes the service publicly reachable without any binding, and it persists
across later image-only deploys.

Service-account needs:
- `roles/cloudkms.signer` on the leaf-OCSP signing key **only**.
- A read-only `DATABASE_URL` whose Postgres role has EXECUTE on
  `lookup_signing_key_revocation` (the same role the verifier uses).
- `roles/secretmanager.secretAccessor` on both secrets above.

Rotating the relay secret has no zero-downtime path, so order it to fail safe:
add the new Secret Manager version, deploy the Worker's new secret first, then
point this service at it. Between those two steps the Worker sends the new value
and this service still expects the old one, so leaf status answers
`internalError` — retriable, and never a wrong status.

Auth: on Cloud Run the KMS call uses the ambient service-account identity
(metadata server). Locally, set `GCP_KMS_SA_JSON` and it signs exactly like
the CA edge functions do.

## Local dev

```sh
cd ocsp-leaf
deno task test                 # pure-core tests (ephemeral signer)
DATABASE_URL=… GCP_KMS_KEY_RESOURCE=… GCP_KMS_SA_JSON=… LEAF_RELAY_SECRET=dev \
  deno task start
# then — openssl can't add headers, so curl the DER by hand:
openssl ocsp -issuer ../verifier/trust-sources/realreel/realreel-claim-signing-ca.pem \
  -serial 0x<hex> -reqout /tmp/req.der -no_nonce
curl -sS --data-binary @/tmp/req.der -o /tmp/resp.der \
  -H 'content-type: application/ocsp-request' \
  -H 'x-realreel-relay-secret: dev' http://localhost:8080/
openssl ocsp -respin /tmp/resp.der -resp_text -no_nonce \
  -issuer ../verifier/trust-sources/realreel/realreel-claim-signing-ca.pem \
  -VAfile ../verifier/trust-sources/realreel/realreel-leaf-ocsp-responder-1.pem
```

Against production, run the same `openssl ocsp -url http://ocsp.realreel.xyz`
one-liner as before — the Worker holds the secret, so acceptance testing through
the real AIA URL needs no header. Only direct-to-Cloud-Run calls do.

## Ops

- Revocation flow: revoke on `user_signing_keys` per the app repo's
  `docs/runbooks/revoke-signing-key.md`; the ledger trigger mirrors it and
  this responder reflects it within the cache window — nothing to do here.
- Responder cert re-issue (annually — the weekly trust-anchor audit WARNs
  60 days out): mint via `ca/tools/build-ca-certs.ts ocsp-leaf`, commit
  the PEM, redeploy this service (the PEM is baked into the image).
