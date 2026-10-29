# realreel-ocsp-leaf

Live RFC 6960 responder for **RealReel leaf certificates** — the per-device
claim-signing certs issued by the Claim Signing ICA. The sibling of the
pre-signed ICA-status Worker in [`../ocsp/`](../ocsp/):

|                | ICA status (`../ocsp/`)                     | Leaf status (this service)                       |
| -------------- | ------------------------------------------- | ------------------------------------------------ |
| Cardinality    | one cert                                    | one serial per enrolled device key               |
| Status source  | sticky KV value, daily refresh              | `issued_certificates` ledger, live               |
| Signing        | pre-signed daily (KMS `realreel-ocsp-root`) | per request (KMS `realreel-ocsp-ica`)            |
| Runtime        | Cloudflare Worker                           | Cloud Run (Deno)                                 |
| Responder cert | root-signed `realreel-ocsp-responder-1.pem` | ICA-signed `realreel-leaf-ocsp-responder-1.pem`  |

The responder cert is ICA-signed because a delegated responder must be certified
by the CA that issued the certificate in question (RFC 6960 §4.2.2.2).

## Status semantics

Read from `public.lookup_signing_key_revocation(serial)` over the app-side
`issued_certificates` ledger (the system of record; survives account deletion):

| Ledger                   | Answer                                                                                     |
| ------------------------ | ------------------------------------------------------------------------------------------ |
| row, `revoked_at IS NULL` | **good** (signed)                                                                          |
| row, `revoked_at` set    | **revoked** (signed; revocationTime = `revoked_at`; the free-text `revoked_reason` isn't a CRLReason, so it's omitted) |
| no row                   | unsigned **unauthorized** (RFC 5019 §2.2.3)                                                |

Every genuinely issued leaf has a ledger row before it leaves the CA, so real
leaves always get a signed answer — and enumerating random serials costs a cheap
indexed lookup, never a KMS signature. Superseded and expired leaves answer
**good**: supersession is app-fleet state, and relying parties judge expiry
from the certificate itself.

`thisUpdate → nextUpdate` is short (`OCSP_LEAF_VALIDITY_HOURS`, default 24, max
72), so a revocation propagates through caches well inside the CP §3.6 72-hour
clock. Successful responses carry `max-age=300`; the unsigned error forms are
`no-store`.

## How requests reach it

RealReel leaves carry `AIA id-ad-ocsp = http://ocsp.realreel.xyz` — the
ICA-status Worker's host. The Worker stays the public front door: it answers ICA CertIDs
from KV and relays **single-CertID requests whose issuer hashes name the ICA**
(RealReel leaves) here — never arbitrary third-party CertIDs. The relay is on
when `LEAF_RESPONDER_ORIGIN` is set in the Worker's `wrangler.toml`.

The relay hop carries a shared secret (`LEAF_RELAY_SECRET`, header
`x-realreel-relay-secret`); without it this service answers `403`. Since the AIA
URL is the Worker, the Worker is the OCSP repository RFC 6960 and CP §4.11
describe and this service only its backend — no OCSP client resolves it, so the
secret costs no conformance claim. It stops the open internet from spending a
KMS signature per request. A missing or wrong secret makes the Worker answer
`internalError`, never a wrong status.

## Endpoints

- `POST /` — DER `OCSPRequest` body (≤ 8 KiB)
- `GET /{url-encoded base64 request}` — RFC 6960 A.1 form
- `GET /healthz` — liveness; `GET /healthz/ready` — DB round-trip probe

Point external uptime checks at `/healthz/ready`: Cloud Run's frontend was
observed answering exactly `/healthz` itself with a 404 (`/healthz/` and every
other path reach the container). Container-side probes are unaffected.

The two probes are the only unauthenticated paths — gating them would put the
secret in the revision spec via `httpGet.httpHeaders`, readable by any
`run.viewer`. They reveal only liveness and DB reachability, but
`/healthz/ready` round-trips a `max: 4` pool, the one path an anonymous flood
can still make this service spend on. To close it, point the startup probe at
`/healthz` and gate `/healthz/ready` with the rest.

Single-CertID requests only (multi-request → `unauthorized`, matching the
Worker). A CertID whose issuer hashes aren't the ICA's → `unauthorized`, with
no ledger lookup or KMS signature spent.

## Deploy (Cloud Run)

Images are built in CI, never locally: this service signs with the hierarchy's
delegated OCSP key, so the deployed bytes must trace to a commit. Tagging
`ocsp-leaf-v<semver>` (matching `deno.json`'s `version`) runs
[`publish-ocsp-leaf-image.yml`](../.github/workflows/publish-ocsp-leaf-image.yml),
which pushes `ghcr.io/wholeearthlabs/realreel-ocsp-leaf:<semver>` with SLSA
build provenance.

```sh
git tag ocsp-leaf-v<semver> && git push origin ocsp-leaf-v<semver>
make deploy-ocsp-leaf TAG=ocsp-leaf-v<semver>   # config: ocsp-leaf/deploy.env
```

`make deploy-ocsp-leaf` verifies that provenance, copies GHCR → Artifact
Registry by digest, and deploys **image-only**: env, secrets, the service
account, and the invoker-check setting all carry over. Anyone can check the same
image (make the GHCR package public first — new packages start private):

```sh
gh attestation verify oci://ghcr.io/wholeearthlabs/realreel-ocsp-leaf:<semver> \
  --repo wholeearthlabs/realreel-c2pa
```

The **first** deploy can't use `make deploy-ocsp-leaf`: an image-only deploy
would create the service without `DATABASE_URL` / `GCP_KMS_KEY_RESOURCE`, and
`main.ts` refuses to start without them. Copy the attested image by digest
yourself, then deploy it with the configuration later image-only deploys
preserve:

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
which a domain-restricted-sharing constraint rejects. Disabling the invoker
check makes the service public without any binding, and it persists across
image-only deploys.

The service account needs:

- `roles/cloudkms.signer` on the leaf-OCSP signing key **only**.
- A read-only `DATABASE_URL` whose Postgres role has EXECUTE on
  `lookup_signing_key_revocation` (the role the verifier uses).
- `roles/secretmanager.secretAccessor` on both secrets above.

**Rotating the relay secret** has no zero-downtime path, so order it to fail
safe: add the new Secret Manager version, deploy the Worker's new secret first,
then point this service at it. In between, leaf status answers `internalError`
— retriable, never a wrong status.

**Auth:** on Cloud Run the KMS call uses the ambient service-account identity.
Locally, set `GCP_KMS_SA_JSON` and it signs exactly as the CA edge functions do.

## Local dev

```sh
cd ocsp-leaf
deno task test                 # pure-core tests (ephemeral signer)
DATABASE_URL=… GCP_KMS_KEY_RESOURCE=… GCP_KMS_SA_JSON=… LEAF_RELAY_SECRET=dev \
  deno task start
# openssl can't add headers, so curl the DER by hand:
openssl ocsp -issuer ../verifier/trust-sources/realreel/realreel-claim-signing-ca.pem \
  -serial 0x<hex> -reqout /tmp/req.der -no_nonce
curl -sS --data-binary @/tmp/req.der -o /tmp/resp.der \
  -H 'content-type: application/ocsp-request' \
  -H 'x-realreel-relay-secret: dev' http://localhost:8080/
openssl ocsp -respin /tmp/resp.der -resp_text -no_nonce \
  -issuer ../verifier/trust-sources/realreel/realreel-claim-signing-ca.pem \
  -VAfile ../verifier/trust-sources/realreel/realreel-leaf-ocsp-responder-1.pem
```

Against production, go through the real AIA URL. The Worker holds the secret, so
no header is needed — only direct-to-Cloud Run calls need it:

```sh
openssl ocsp -issuer ../verifier/trust-sources/realreel/realreel-claim-signing-ca.pem \
  -serial 0x<hex> -url http://ocsp.realreel.xyz -resp_text -no_nonce \
  -VAfile ../verifier/trust-sources/realreel/realreel-leaf-ocsp-responder-1.pem
```

## Ops

- **Revocation:** revoke on `user_signing_keys` per the app repo's
  `docs/runbooks/revoke-signing-key.md`. The ledger trigger mirrors it, and this
  responder reflects it within the cache window — nothing to do here.
- **Responder cert re-issue** (annual — the weekly trust-anchor audit WARNs 60
  days out): mint via `ca/tools/build-ca-certs.ts ocsp-leaf`, commit the PEM,
  and redeploy (the PEM is baked into the image).
