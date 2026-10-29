# realreel-pki

Cloudflare Worker that publishes the **RealReel C2PA CA**'s public certificates
at `pki.realreel.xyz`. Operated by Whole Earth Labs LLC.

## What it serves

| Path                             | Content-Type              |                                            |
| -------------------------------- | ------------------------- | ------------------------------------------ |
| `/realreel-c2pa-root.cer`        | `application/pkix-cert`   | root, DER — the ICA's AIA `caIssuers` target |
| `/realreel-c2pa-root.pem`        | `application/x-pem-file`  | root, PEM                                  |
| `/realreel-claim-signing-ca.cer` | `application/pkix-cert`   | ICA, DER — new-hierarchy leaves' AIA `caIssuers` target |
| `/realreel-claim-signing-ca.pem` | `application/x-pem-file`  | ICA, PEM                                   |
| `/`                              | `text/html`               | index (shows the root SHA-256)             |

RealReel-signed manifests carry the full chain (leaf + Claim Signing ICA)
in-band, so validators normally need only the anchor. The AIA `caIssuers`
pointers let a party missing a link fetch it here: a leaf points at the ICA,
the ICA at the root.

Responses are CORS-open (`access-control-allow-origin: *`) for browser-based
C2PA validators. Public certificates only — the CA keys live in a Cloud KMS HSM.

## Source of truth and tests

The Worker imports the PEMs from `../verifier/trust-sources/realreel/` (no
copies live here) and derives the DER and fingerprint at request time, so the
published bytes can't drift from the verifier's trust anchors.

```bash
npm run test:pki   # from the repo root
```

## Deploy

Needs the `realreel.xyz` zone on this Cloudflare account and wrangler auth
(`npx wrangler login`).

```bash
cd pki && npx wrangler deploy
```

`custom_domain = true` in `wrangler.toml` provisions the DNS record and edge TLS
for `pki.realreel.xyz` on the first deploy.

## Cloudflare zone settings

Two defaults break AIA fetches while a browser and a plain `curl` still succeed:

- **Always Use HTTPS.** AIA URLs are `http://` by PKIX convention; with this on,
  they get a 301 to https, which standard path builders follow. Fine to leave on,
  or skip the redirect with a Configuration Rule for this host.
- **Bot Fight Mode / Browser Integrity Check / a raised Security Level.** These
  challenge requests with unusual or absent User-Agents — exactly what AIA path
  builders (openssl, Java, Go, embedded C2PA validators) send — and the path
  builder then tries to parse the HTML challenge as a DER certificate. **Exempt
  `pki.realreel.xyz` from every challenge/bot rule** (a WAF skip or per-host
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

Every issued certificate bakes in its AIA `caIssuers` URL, so those paths are
fixed. Fingerprints are derived from the PEMs — there's never one to update by
hand.

- **ICA (Claim Signing CA) rotation** — a new ICA under the same root: update
  `verifier/trust-sources/realreel/realreel-claim-signing-ca.pem` and redeploy.
  Old content carries the old ICA in-band, so both stay valid.
- **Root rotation** (rare — the root is 25 years): don't overwrite the DER at
  `/realreel-c2pa-root.cer`; every ICA anchored to the old root points there.
  Serve a **certs-only CMS (PKCS#7) bundle** of both roots at that path (a valid
  `caIssuers` payload per RFC 5280), and keep both reachable until the last
  certificate chaining to the old root expires — see the wind-down runbook.
