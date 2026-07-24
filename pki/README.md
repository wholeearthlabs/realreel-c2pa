# realreel-pki

Cloudflare Worker that publishes the **RealReel C2PA CA** public certificates at
`pki.realreel.xyz`, operated by Whole Earth Labs LLC.

## What it serves

Public certificate repository for the RealReel C2PA CA. It serves the root (the
trust anchor) and the Claim Signing intermediate:

| Path | Content-Type | |
|---|---|---|
| `/realreel-c2pa-root.cer` | `application/pkix-cert` | root, DER — the AIA `caIssuers` target |
| `/realreel-c2pa-root.pem` | `application/x-pem-file` | root, PEM |
| `/realreel-claim-signing-ca.cer` | `application/pkix-cert` | ICA, DER |
| `/realreel-claim-signing-ca.pem` | `application/x-pem-file` | ICA, PEM |
| `/` | `text/html` | index (shows the root SHA-256) |

RealReel-signed manifests carry the full chain (leaf + Claim Signing ICA)
in-band, so validators normally need only the anchor. The **ICA** additionally
carries `AIA caIssuers -> http://pki.realreel.xyz/realreel-c2pa-root.cer`, so a
party holding the ICA but not the root can fetch the root here and terminate the
chain. Publishing the ICA too is conventional for a CA repository and is
forward-compatible with the leaf AIA planned for the next hierarchy revision.

All responses are CORS-open (`access-control-allow-origin: *`) so browser-based
C2PA validators can fetch from any origin. Public certificates only — no private
key material is ever involved; the CA keys live in Cloud KMS HSM.

## Source of truth and tests

The Worker imports the certificate PEMs directly from
`../verifier/trust-sources/realreel/` (no copies live in `pki/`) and derives the
DER form and the fingerprint from them at request time, so the published bytes
can never drift from the verifier's trust anchors. The router is unit-tested:

```bash
deno test --allow-read pki/router_test.ts
```

## Deploy

Requires the `realreel.xyz` zone on this Cloudflare account and wrangler auth
(`npx wrangler login`).

```bash
cd pki
npx wrangler deploy
```

`routes` in `wrangler.toml` uses `custom_domain = true`, so the first deploy
provisions the DNS record and edge TLS certificate for `pki.realreel.xyz`
automatically.

## Cloudflare zone settings

Two default zone settings routinely break AIA fetches while a browser and a
plain `curl` still succeed — verify these before trusting the endpoint:

- **Always Use HTTPS.** The AIA URL is `http://` by PKIX convention. With this
  on, http requests get a 301 to https, which standard path builders follow.
  Fine to leave on; to avoid the redirect, add a Configuration Rule disabling it
  for `pki.realreel.xyz/realreel-c2pa-root.cer`.
- **Bot Fight Mode / Browser Integrity Check / a raised Security Level.** These
  challenge or 403 requests with unusual or absent User-Agents — exactly what AIA
  path builders (openssl, Java, Go, embedded C2PA validators) send. The failure
  is invisible from a browser and from `curl` with a normal UA, so the Verify
  steps below can pass while real fetches receive an HTML challenge page that a
  path builder then tries to parse as a DER certificate. **Exempt
  `pki.realreel.xyz` from all challenge/bot rules** (a WAF skip or per-host
  Configuration Rule).

## Verify

```bash
curl -sI https://pki.realreel.xyz/realreel-c2pa-root.cer
# 200 ; content-type: application/pkix-cert ; access-control-allow-origin: *

curl -s https://pki.realreel.xyz/realreel-c2pa-root.cer \
  | openssl x509 -inform der -noout -subject -fingerprint -sha256
# subject= ... CN=RealReel C2PA Root CA
# SHA-256 must match the fingerprint published at https://pki.realreel.xyz/
```

## Rotation

The AIA `caIssuers` URL baked into every issued certificate is fixed at
`http://pki.realreel.xyz/realreel-c2pa-root.cer`. That immutability shapes both
rotation cases. The Worker derives DER and fingerprints from the trust-source
PEMs, so there is never a hand-maintained fingerprint to update.

- **Intermediate (Claim Signing CA) rotation** — a new ICA under the same root:
  update `verifier/trust-sources/realreel/realreel-claim-signing-ca.pem` and
  redeploy. The root served here is unchanged; old content carries the old ICA
  in-band, so both remain valid.

- **Root rotation** (rare — the root is 25 y): do **not** overwrite the single
  DER at `/realreel-c2pa-root.cer` with the new root. Every ICA still anchored to
  the old root points its AIA at that exact path, so overwriting it breaks those
  chains. Instead, serve a **certs-only CMS (PKCS#7) bundle** containing both the
  old and new roots at that path (a valid `caIssuers` payload per RFC 5280), and
  keep both reachable until the last certificate chaining to the old root has
  expired — see the wind-down runbook.
