# Verifier deploy

Cloud Run microservice. Self-contained; no app-side coupling.

For rollback, diagnostics, rotations, and monitoring, see [OPERATIONS.md](OPERATIONS.md).

## Env vars

| Var | Source | Shape |
|---|---|---|
| `PORT` | Cloud Run default | `8080` |
| `NODE_ENV` | Image ENV | `production` |
| `VERIFIER_SHARED_SECRET` | `openssl rand -base64 48`; must match Supabase Edge function secret of same name | `<48-byte b64>` |
| `DATABASE_URL` | Supabase → Connect → **Shared Pooler** (Supavisor), Transaction mode, port 6543, `verifier_readonly` role. Username is **tenant-qualified** (`<role>.<project-ref>`). **Cloud Run egress is IPv4-only — see the warning below.** | `postgresql://verifier_readonly.<project-ref>:<pw>@aws-0-<region>.pooler.supabase.com:6543/postgres` |
| `ASSET_STORAGE_HOST_REGEX` | URL shape match; first SSRF layer (asset storage, typically Supabase Storage) | `^https://<project-ref>\.supabase\.co/storage/v1/object/sign/` |
| `ASSET_STORAGE_HOST_ALLOWLIST` | Authoritative host allowlist; comma-separated, lowercase | `<project-ref>.supabase.co` |
| `SENTRY_DSN` | Optional; skip for dry-run | `https://...@...ingest.sentry.io/...` |
| `TRUST_SOURCES_PATH` | Image default; rarely overridden | `/app/trust-sources.yaml` |
| `PLAY_INTEGRITY_PACKAGE_NAME` | Android package name, matches Play Console listing | `com.realreel.app` |
| `PLAY_INTEGRITY_CLOUD_PROJECT_NUMBER` | Google Cloud project number (NOT project ID) issuing Play Integrity tokens for this build. Must match the `CLOUD_PROJECT_NUMBER` hardcoded const in `native/android/.../PhotoAttestModule.kt` | `123456789012` |
| `ATTESTATION_REQUIRED` | **⚠️ Most safety-critical setting.** Strict per-platform require-presence of Stage 2 (upload-time) attestation per the signing key's platform: iOS → `org.realreel.app_attest`, Android → `org.realreel.play_integrity`. (Stage 1 carries no per-capture device-health check — enrollment-only trust.) **In production this MUST be set explicitly to `true` or `false` — an unset or ambiguous value FAILS CLOSED (the verifier throws at startup).** | `true` |

> **⚠️ `DATABASE_URL` must use the Supabase _Shared_ Pooler (Supavisor), over IPv4.**
> Cloud Run — like serverless platforms generally — has **IPv4-only egress**. Supabase's
> **Direct connection** and the **Dedicated Pooler** (`db.<project-ref>.supabase.co`) are
> **IPv6-only** unless you buy the paid IPv4 add-on, so they are simply **unreachable from
> Cloud Run**. You MUST use the **Shared Pooler** (Supavisor), Transaction mode — it is
> IPv4-compatible:
>
> ```
> postgresql://verifier_readonly.<project-ref>:<pw>@aws-0-<region>.pooler.supabase.com:6543/postgres
> ```
>
> Two things differ from the naïve URL: the username is **tenant-qualified**
> (`verifier_readonly.<project-ref>`, not bare `verifier_readonly`), and the host is the
> **regional shared pooler** (`aws-0-<region>.pooler.supabase.com` — *not*
> `<project-ref>.pooler.supabase.com` and *not* `db.<project-ref>.supabase.co`). In the
> dashboard this is **Connect → Shared Pooler → Transaction** (not "Dedicated Pooler").
>
> **Failure symptom if you get this wrong:** the `/healthz/ready` startup probe never goes
> green — the DB connection silently times out, the revision never serves traffic, and
> nothing in the logs obviously points at IPv6; it just reads like a slow or hung database.

### Production setup (recap)

For a real production deploy, set ALL of these in the Cloud Run env block:

```
PLAY_INTEGRITY_PACKAGE_NAME=com.realreel.app
PLAY_INTEGRITY_CLOUD_PROJECT_NUMBER=<numeric, from Google Cloud console>
ATTESTATION_REQUIRED=true
```

The Cloud Run runtime service account also needs `roles/playintegrity.user` on the Google Cloud project named above. See **Deploy step 3** below for the grant command + service-account choice.

> **Attestation status:** `ATTESTATION_REQUIRED` stays **off** in production until the upload-time (Stage 2) attestation path is required on both platforms. The verifier wiring + config are in place and exercised by the test suite. (Per-capture Stage-1 device-health attestation was dropped — enrollment-only trust.)

### What each combination means

> **⚠️ Fail-closed in production.** `ATTESTATION_REQUIRED` is the single most safety-critical verifier setting — when lenient, the verifier accepts uploads carrying **no attestation**. When `NODE_ENV=production`, this var MUST be set **explicitly** to `true` or `false`. If it is unset or any other value (a typo, `1`, `yes`, empty string), `loadConfig()` **throws at startup** rather than silently defaulting to lenient. Set `=true` for strict per-platform enforcement, or `=false` to deliberately accept the lenient gate. Outside production the legacy lenient-by-default behavior applies (local dev leaves it unset).

| `PLAY_INTEGRITY_*` set? | `ATTESTATION_REQUIRED` | Behavior |
|---|---|---|
| Yes (both) | `true` | **Production posture.** Stage 2 (upload) requires the platform's attestation envelope: iOS-signed Stage 2 must carry `org.realreel.app_attest`; Android-signed Stage 2 must carry `org.realreel.play_integrity` (decoded server-side via Google's `decodeIntegrityToken` API). Missing required envelope → `ATTESTATION_MISSING`. (Stage 1 carries no per-capture device-health check — enrollment-only trust.) |
| Yes (both) | `false` (or unset, non-prod) | "Lenient-decode": Google decode runs when assertion present, but missing assertion still accepted. Useful for testing decode + verdict enforcement against real Google credentials without locking out unattested uploads. |
| Neither set | `false` (or unset, non-prod) | **Local dev posture.** Lenient — structural envelope check + nonce burn only. Missing assertion accepted. No Google credentials required to boot. |
| Either one of `PLAY_INTEGRITY_*` set, other unset | (any) | **Startup error.** Partial config is a typo; refuse to start. |
| Neither set | `true` | **Startup error.** Can't require an envelope we have no credentials to decode. |
| (any) | unset / ambiguous, with `NODE_ENV=production` | **Startup error.** Production fails closed on an ambiguous `ATTESTATION_REQUIRED` — must be explicitly `true` or `false`. |
| `NODE_ENV=production` + no `PLAY_INTEGRITY_*` | `false` | Emits WARNING log at startup (`category: "play-integrity"`). Alert on it in Cloud Logging to catch deploys that forgot the config entirely. |

### Why `ATTESTATION_REQUIRED` exists as a separate flag

Even with `PLAY_INTEGRITY_*` set, the verifier would otherwise still tolerate manifests that arrive **without** the assertion — that's the lenient default useful during gradual rollout, but a bypass surface in production. `ATTESTATION_REQUIRED=true` is what closes the gate. Without it, a tampered dev build that strips the assertion entirely would pass production verification (cert chain + nonce checks still apply, but the attestation requirement doesn't).

The flag is separate from `PLAY_INTEGRITY_*` because the underlying capabilities are separate: `PLAY_INTEGRITY_*` enables *Google-side decoding* of present assertions (the verifier passes the opaque token to `decodeIntegrityToken` for signature validation + verdict extraction), while `ATTESTATION_REQUIRED` enforces *presence* of the right assertion per platform. iOS App Attest doesn't need credentials, but it does benefit from required-presence enforcement.

### Stage 1 capture: enrollment-only trust

Stage 1 (capture) carries **no per-capture device-health attestation**. Trust in
the capture rests on its cert chaining to a trusted root — the RealReel CA at
enrollment, or a trusted vendor (Pixel) for a wrapped third-party capture — plus
the structural fresh-capture rule + the capture-action allowlist (`c2pa.created`
only). This is the same enrollment-only model Pixel's C2PA camera and iOS App
Attest both use. Any legacy embedded Stage-1 `app_attest` / `key_attest` envelope
on an older capture is **ignored** (backward-compatible).

Attestation enforcement applies only to **Stage 2** (the upload), as described
above.

## First-time bootstrap

One-time setup before the first deploy; skip if already provisioned. Production is bootstrapped — this section is for a clean second-environment standup (e.g. staging) or disaster recovery.

Two distinct GCP projects are involved, by design — they map to different trust boundaries:

| Project | What it holds | Why separate |
|---|---|---|
| **Verifier-hosting project** | Cloud Run service, Artifact Registry, runtime SA, Sentry-side observability | Day-to-day deploys; broader IAM surface; you'll rotate images here frequently |
| **CA project** | Cloud KMS keyring + the issuing CA key, KMS signer SA used by the `register-signing-key` edge function | Custodial scope; rotates ~never; tighter IAM. Keep your CA custody model documented separately. |

In a small org these can be the same GCP project; in production they're separate.

### 1. Provision the verifier-hosting project

```bash
# Create or pick the project that will host Cloud Run + Artifact Registry.
gcloud projects create <verifier-project> --name="RealReel Verifier"

# Enable the APIs the verifier needs at runtime.
gcloud services enable \
  run.googleapis.com \
  artifactregistry.googleapis.com \
  playintegrity.googleapis.com \
  --project=<verifier-project>

# Artifact Registry repo for the verifier image.
gcloud artifacts repositories create verifier \
  --repository-format=docker \
  --location=us-central1 \
  --description="RealReel verifier images" \
  --project=<verifier-project>
```

### 2. Provision the CA project

Summary (keep your full CA custody model documented separately): create a KMS keyring + issuing key (e.g. keyring `realreel-ca`, key `realreel-intermediate`, algorithm `ec-sign-p256-sha256`, protection level `hsm`) and a pair of service accounts (one for production, one for dev) with `roles/cloudkms.signer` + `roles/cloudkms.publicKeyViewer` scoped to the key only. The verifier itself does NOT call Cloud KMS — that's the edge-function side. This step is listed here so the bootstrap is end-to-end checkable.

### 3. Link the Play Console listing to the Play Integrity project

Done once per app + Play Integrity project pair, via Play Console UI:

1. Play Console → your app → **App integrity** → **Play Integrity API** → **Link project**.
2. Pick the GCP project whose number you'll set as `PLAY_INTEGRITY_CLOUD_PROJECT_NUMBER`. Most teams use the verifier-hosting project here — having Play Integrity colocate with Cloud Run keeps IAM in one place.
3. Confirm the project number matches the `CLOUD_PROJECT_NUMBER` hardcoded in `native/android/.../PhotoAttestModule.kt` (and in your Cloud Run env). Mismatch = 422 from `decodeIntegrityToken`. See the Diagnostics table in [OPERATIONS.md](OPERATIONS.md#diagnostics-play-integrity-decode-failures).
4. **Enable Optional device labels (sdkVersion) in the response settings.** Play Console → App integrity → Play Integrity API → Response settings → enable the **Device information** block (specifically the `sdkVersion` field under `deviceAttributes`). The verifier requires this for the Android-12 sdkVersion gate at `play_integrity.ts` `enforceVerdicts` — STRONG on Android ≤12 carries no patch-currency signal ([Google Play Integrity verdicts](https://developer.android.com/google/play/integrity/verdicts)), so the verifier refuses to honor STRONG without `sdkVersion >= 33`. The gate fails closed when `deviceAttributes.sdkVersion` is absent: every Android upload returns `ATTESTATION_INVALID` with the message `Play Integrity deviceAttributes.sdkVersion missing or non-numeric — Play Console Optional device labels must be enabled`.

**Verifying the link worked:** without the link, `decodeIntegrityToken` returns HTTP 404 for any token from this app. Re-check Play Console → App integrity if you see those.

**Verifying step 4 worked:** after enabling Optional device labels, run a fresh upload from a real Play-Store-installed device. The verifier should accept it. If every Android upload still fails with `sdkVersion missing`, double-check the Response settings toggle — the change can take a few minutes to propagate.

### 4. Provision Supabase secrets the verifier image expects

The Cloud Run runtime reads `DATABASE_URL`, `VERIFIER_SHARED_SECRET`, `ASSET_STORAGE_HOST_*`, and `SENTRY_DSN` from its env block. Source values:

- `DATABASE_URL` → Supabase project → Connect → **Shared Pooler** (Supavisor), mode `transaction`, port `6543`, role `verifier_readonly` (created by the schema migration; password set in **Deploy step 1** below). The username is tenant-qualified (`verifier_readonly.<project-ref>`) and the host is `aws-0-<region>.pooler.supabase.com`. **Do not** use the Direct connection or the Dedicated Pooler (`db.<project-ref>.supabase.co`) — both are IPv6-only and unreachable from Cloud Run's IPv4-only egress. See the warning under the env-vars table.
- `VERIFIER_SHARED_SECRET` → `openssl rand -base64 48`; save in your secret manager, mirror to the Supabase Edge function secret of the same name.
- `ASSET_STORAGE_HOST_REGEX` + `ASSET_STORAGE_HOST_ALLOWLIST` → both derive from your asset-storage host (your Supabase project ref, for a Supabase Storage backend). See the env-vars table above.
- `SENTRY_DSN` → optional; create a Sentry project named `realreel-verifier` if you want capture.

Once these are in hand, you're ready for the **Deploy** flow below.

## Deploy

1. **`verifier_readonly` password.** The schema migration creates the role with a placeholder password. In the Supabase SQL editor: `ALTER USER verifier_readonly WITH PASSWORD '<new>';`. The `DATABASE_URL` above embeds this password.

2. **Build + push** the container image. It builds from the **repo root** (not `verifier/`) so the `@realreel/c2pa-trust-core` workspace dep is compiled from source — no published-npm dependency, no publish-before-deploy — and is pinned to `linux/amd64` (Cloud Run's arch):

   ```bash
   # from the repo root:
   docker build -f verifier/Dockerfile -t <region>-docker.pkg.dev/<project>/verifier/realreel-verifier:<tag> .
   docker push <region>-docker.pkg.dev/<project>/verifier/realreel-verifier:<tag>
   ```

   (Cloud Build: keep the context at the repo root, pointing at `verifier/Dockerfile`.)

3. **Play Integrity IAM grant.** The verifier calls Google's `decodeIntegrityToken` API on every Android upload; it needs the `roles/playintegrity.user` role on the Google Cloud project that issues your Play Integrity tokens (same project as `PLAY_INTEGRITY_CLOUD_PROJECT_NUMBER` above). Application Default Credentials picks up the Cloud Run runtime SA automatically — no credential file needed.

   The grant goes on the **Play Integrity project** (where tokens are issued). The SA that receives the grant lives in the **verifier-hosting project** (where Cloud Run runs). These two projects can be the same or different; the grant works either way.

   **Service-account choice:**

   - **Dedicated runtime SA (recommended, even for the first deploy):** create one SA per service so the `roles/playintegrity.user` grant — and every other runtime permission — is auditable and attached to a stable identity. This is the SA the grant lands on at go-strict, so standing it up now avoids re-pointing IAM later:

     ```bash
     gcloud iam service-accounts create realreel-verifier \
       --display-name="RealReel verifier (Cloud Run runtime)" \
       --project=<verifier-project>

     # <play-integrity-project-number> = PLAY_INTEGRITY_CLOUD_PROJECT_NUMBER.
     gcloud projects add-iam-policy-binding <play-integrity-project-number> \
       --member="serviceAccount:realreel-verifier@<verifier-project>.iam.gserviceaccount.com" \
       --role="roles/playintegrity.user"
     ```

     Then deploy Cloud Run with `--service-account=realreel-verifier@<verifier-project>.iam.gserviceaccount.com` in step 4 so the runtime actually uses this SA.

   - **Compute Engine default SA (quick path):** Cloud Run otherwise falls back to the Compute Engine default SA at `<verifier-project-number>-compute@developer.gserviceaccount.com`. Convenient, but coarse-grained (shared by every Compute/Cloud Run workload in the project) and — the gotcha on a **fresh** project — it **does not exist until the Compute Engine API has been enabled at least once**. A brand-new verifier-hosting project that only enabled `run`/`artifactregistry`/`playintegrity` (per **First-time bootstrap step 1**) won't have it, and the grant below fails with `service account ... does not exist`. Enable `compute.googleapis.com` first, or just use the dedicated SA above. Grant:

     ```bash
     # <play-integrity-project-number> is PLAY_INTEGRITY_CLOUD_PROJECT_NUMBER —
     #   the project that ISSUES the tokens; the binding goes here.
     # <verifier-project-number> is the project hosting the Cloud Run service,
     #   where the runtime SA lives (often the same project).
     gcloud projects add-iam-policy-binding <play-integrity-project-number> \
       --member="serviceAccount:<verifier-project-number>-compute@developer.gserviceaccount.com" \
       --role="roles/playintegrity.user"
     ```

   **Verifying the grant worked:** after deploy, hit `/verify` with any Android-signed manifest. If you see HTTP 503 logs with `Play Integrity decode rejected (HTTP 401)` or `(HTTP 403)`, the SA grant is missing or scoped to the wrong project.

4. **Deploy** the pushed image to Cloud Run with the env vars above, the dedicated runtime SA from step 3, and a startup probe on `GET /healthz/ready`. Readiness round-trips `lookup_signing_key_revocation` — a misconfigured `DATABASE_URL` or revoked grant fails the probe instead of letting bad instances serve `/verify`.

   **Put the secret-bearing values in Secret Manager, not plaintext env vars.** `DATABASE_URL` (embeds the DB password), `VERIFIER_SHARED_SECRET`, and `SENTRY_DSN` should be wired with `--set-secrets`; `--set-env-vars` would bake them into the revision config, where anyone with `run.revisions.get` can read them back. The non-secret policy (package name, project number, attestation + SSRF settings) stays in `--set-env-vars`.

   ```bash
   # One-time: store the secret values as Secret Manager secrets.
   printf %s "$DATABASE_URL"           | gcloud secrets create verifier-database-url  --data-file=- --project=<verifier-project>
   printf %s "$VERIFIER_SHARED_SECRET" | gcloud secrets create verifier-shared-secret --data-file=- --project=<verifier-project>
   printf %s "$SENTRY_DSN"             | gcloud secrets create verifier-sentry-dsn     --data-file=- --project=<verifier-project>
   # Let the runtime SA read them.
   for s in verifier-database-url verifier-shared-secret verifier-sentry-dsn; do
     gcloud secrets add-iam-policy-binding "$s" \
       --member="serviceAccount:realreel-verifier@<verifier-project>.iam.gserviceaccount.com" \
       --role="roles/secretmanager.secretAccessor" --project=<verifier-project>
   done

   gcloud run deploy realreel-verifier \
     --image=<region>-docker.pkg.dev/<project>/verifier/realreel-verifier:<tag> \
     --region=<region> --project=<verifier-project> \
     --service-account=realreel-verifier@<verifier-project>.iam.gserviceaccount.com \
     --set-secrets="DATABASE_URL=verifier-database-url:latest,VERIFIER_SHARED_SECRET=verifier-shared-secret:latest,SENTRY_DSN=verifier-sentry-dsn:latest" \
     --set-env-vars="^@^ATTESTATION_REQUIRED=true@PLAY_INTEGRITY_PACKAGE_NAME=com.realreel.app@PLAY_INTEGRITY_CLOUD_PROJECT_NUMBER=<numeric>@ASSET_STORAGE_HOST_ALLOWLIST=<project-ref>.supabase.co@ASSET_STORAGE_HOST_REGEX=^https://<project-ref>\.supabase\.co/storage/v1/object/sign/" \
     --startup-probe=httpGet.path=/healthz/ready,httpGet.port=8080,failureThreshold=6,periodSeconds=5,timeoutSeconds=4
   ```

   (The `^@^` prefix sets `@` as the `--set-env-vars` delimiter so the regex value can contain literal commas if you extend it; with the values above a plain comma-delimited list works too.)

   The startup probe gives the container **6 × 5 s = 30 s** to report ready before Cloud Run tears the revision down (`failureThreshold=6`, `periodSeconds=5`), with `timeoutSeconds=4` bounding each probe request. The image runs **node 24 / OpenSSL 3.5**, so confirm the readiness probe goes green on first deploy — the Postgres TLS cert must be ≥2048-bit RSA / ≥224-bit ECC (managed Postgres meets this). If the probe never goes green, the first suspect is `DATABASE_URL`: re-check the IPv4 Shared-Pooler warning under the env-vars table.

5. **Wire the Edge function side.** In Supabase Edge secrets:
   - `VERIFIER_URL` = Cloud Run service URL
   - `VERIFIER_SHARED_SECRET` = same value as Cloud Run's

6. **Orphan sweeper secrets** (one-time; the orphan-storage sweeper reclaims media rows whose upload never completed verification).

   In the Supabase SQL editor:

   ```sql
   SELECT vault.create_secret(
     'https://<project-ref>.supabase.co/functions/v1/sweep-orphan-storage',
     'sweep_orphan_storage_url'
   );

   -- Generate locally: openssl rand -base64 48 — paste here AND in the CLI step below.
   SELECT vault.create_secret('<random-48-byte-b64>', 'sweep_orphan_storage_secret');
   ```

   Then from the CLI:

   ```bash
   supabase secrets set CRON_SECRET='<same-random-48-byte-b64>'
   ```

## Transparency: the published GHCR image

Every tagged verifier release is also built and pushed to
**`ghcr.io/wholeearthlabs/realreel-verifier`** with SLSA build provenance, by
[`.github/workflows/publish-verifier-image.yml`](../.github/workflows/publish-verifier-image.yml).
This mirrors the npm Trusted-Publishing provenance on the published packages: it
lets anyone pull, run, and independently verify the published image and how it was
built. Tag a release `verifier-v<semver>` (e.g. `verifier-v1.4.0`) to trigger it, or
run the workflow manually (`workflow_dispatch`).

```bash
docker pull ghcr.io/wholeearthlabs/realreel-verifier:<tag>
gh attestation verify oci://ghcr.io/wholeearthlabs/realreel-verifier:<tag> \
  --repo wholeearthlabs/realreel-c2pa
```

The image is built from the same Dockerfile, `--platform=linux/amd64`, and
monorepo-root context as the **Deploy** flow above, so a given commit produces a
reproducible image you can pull, run, and inspect — no special access required.
