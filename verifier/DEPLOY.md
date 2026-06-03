# Verifier deploy + rotations

Cloud Run microservice. Self-contained; no app-side coupling.

## Env vars

| Var | Source | Shape |
|---|---|---|
| `PORT` | Cloud Run default | `8080` |
| `NODE_ENV` | Image ENV | `production` |
| `VERIFIER_SHARED_SECRET` | `openssl rand -base64 48`; must match Supabase Edge function secret of same name | `<48-byte b64>` |
| `DATABASE_URL` | Supabase → Connection pooling (transaction mode, port 6543), `verifier_readonly` role | `postgres://verifier_readonly:<pw>@<ref>.pooler.supabase.com:6543/postgres` |
| `ASSET_STORAGE_HOST_REGEX` | URL shape match; first SSRF layer (asset storage, typically Supabase Storage) | `^https://<project-ref>\.supabase\.co/storage/v1/object/sign/` |
| `ASSET_STORAGE_HOST_ALLOWLIST` | Authoritative host allowlist; comma-separated, lowercase | `<project-ref>.supabase.co` |
| `SENTRY_DSN` | Optional; skip for dry-run | `https://...@...ingest.sentry.io/...` |
| `TRUST_SOURCES_PATH` | Image default; rarely overridden | `/app/trust-sources.yaml` |
| `PLAY_INTEGRITY_PACKAGE_NAME` | Android package name, matches Play Console listing | `com.realreel.app` |
| `PLAY_INTEGRITY_CLOUD_PROJECT_NUMBER` | Google Cloud project number (NOT project ID) issuing Play Integrity tokens for this build. Must match the `CLOUD_PROJECT_NUMBER` hardcoded const in `native/android/.../PhotoAttestModule.kt` | `123456789012` |
| `ATTESTATION_REQUIRED` | **⚠️ Most safety-critical setting.** Strict per-platform require-presence of Stage 2 (upload-time) attestation per the signing key's platform: iOS → `org.realreel.app_attest`, Android → `org.realreel.play_integrity`. (Stage 1 carries no per-capture device-health check — enrollment-only trust.) **In production this MUST be set explicitly to `true` or `false` — an unset or ambiguous value FAILS CLOSED (the verifier throws at startup).** | `true` |

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
| **CA project** (`realreel-certificate-authority`) | Cloud KMS keyring + the issuing CA key, KMS signer SA used by `register-signing-key` edge function | Custodial scope; rotates ~never; tighter IAM. See RealReel's internal CA custody documentation for the full custody model. |

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

Already documented in RealReel's internal CA custody documentation. Summary: create the KMS keyring `realreel-ca`, the key `realreel-intermediate` (algorithm `ec-sign-p256-sha256`, protection level `hsm`), and the two service accounts (`signing-key-issuer@` for production, `signing-key-issuer-dev@` for dev) with `roles/cloudkms.signer` + `roles/cloudkms.publicKeyViewer` scoped to the key only. The verifier itself does NOT call Cloud KMS — that's the edge-function side. This step is listed here so the bootstrap is end-to-end checkable.

### 3. Link the Play Console listing to the Play Integrity project

Done once per app + Play Integrity project pair, via Play Console UI:

1. Play Console → your app → **App integrity** → **Play Integrity API** → **Link project**.
2. Pick the GCP project whose number you'll set as `PLAY_INTEGRITY_CLOUD_PROJECT_NUMBER`. Most teams use the verifier-hosting project here — having Play Integrity colocate with Cloud Run keeps IAM in one place.
3. Confirm the project number matches the `CLOUD_PROJECT_NUMBER` hardcoded in `native/android/.../PhotoAttestModule.kt` (and in your Cloud Run env). Mismatch = 422 from `decodeIntegrityToken`. See the Diagnostics table.
4. **Enable Optional device labels (sdkVersion) in the response settings.** Play Console → App integrity → Play Integrity API → Response settings → enable the **Device information** block (specifically the `sdkVersion` field under `deviceAttributes`). The verifier requires this for the Android-12 sdkVersion gate at `play_integrity.ts` `enforceVerdicts` — STRONG on Android ≤12 carries no patch-currency signal ([Google Play Integrity verdicts](https://developer.android.com/google/play/integrity/verdicts)), so the verifier refuses to honor STRONG without `sdkVersion >= 33`. The gate fails closed when `deviceAttributes.sdkVersion` is absent: every Android upload returns `ATTESTATION_INVALID` with the message `Play Integrity deviceAttributes.sdkVersion missing or non-numeric — Play Console Optional device labels must be enabled`.

**Verifying the link worked:** without the link, `decodeIntegrityToken` returns HTTP 404 for any token from this app. Re-check Play Console → App integrity if you see those.

**Verifying step 4 worked:** after enabling Optional device labels, run a fresh upload from a real Play-Store-installed device. The verifier should accept it. If every Android upload still fails with `sdkVersion missing`, double-check the Response settings toggle — the change can take a few minutes to propagate.

### 4. Provision Supabase secrets the verifier image expects

The Cloud Run runtime reads `DATABASE_URL`, `VERIFIER_SHARED_SECRET`, `ASSET_STORAGE_HOST_*`, and `SENTRY_DSN` from its env block. Source values:

- `DATABASE_URL` → Supabase project settings → Connection pooling, mode `transaction`, port `6543`, role `verifier_readonly` (created by the schema migration; password set in **Deploy step 1** below).
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

   - **Default (recommended for first deploy):** Cloud Run uses the Compute Engine default SA at `<verifier-project-number>-compute@developer.gserviceaccount.com`. It exists automatically once the Compute API is enabled. Grant:

     ```bash
     # <play-integrity-project-number> is PLAY_INTEGRITY_CLOUD_PROJECT_NUMBER —
     #   the project that ISSUES the tokens; the binding goes here.
     # <verifier-project-number> is the project hosting the Cloud Run service,
     #   where the runtime SA lives (often the same project).
     gcloud projects add-iam-policy-binding <play-integrity-project-number> \
       --member="serviceAccount:<verifier-project-number>-compute@developer.gserviceaccount.com" \
       --role="roles/playintegrity.user"
     ```

   - **Custom SA (cleaner long-term):** create a dedicated SA per service so IAM is auditable:

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

   **Verifying the grant worked:** after deploy, hit `/verify` with any Android-signed manifest. If you see HTTP 503 logs with `Play Integrity decode rejected (HTTP 401)` or `(HTTP 403)`, the SA grant is missing or scoped to the wrong project.

4. **Deploy** the pushed image to Cloud Run with the env vars above and a startup probe on `GET /healthz/ready` (`failureThreshold: 6`, `periodSeconds: 5`). Readiness round-trips `lookup_signing_key_revocation` — a misconfigured `DATABASE_URL` or revoked grant fails the probe instead of letting bad instances serve `/verify`. If using a custom SA (step 3 above), pass `--service-account=<sa-email>`. The image runs **node 24 / OpenSSL 3.5**, so confirm the readiness probe goes green on first deploy — the Postgres TLS cert must be ≥2048-bit RSA / ≥224-bit ECC (managed Postgres meets this).

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

## Rollback

A bad deploy gets rolled back at the Cloud Run revision layer — every `gcloud run deploy` (or container push) creates a new revision, and Cloud Run keeps the prior ones for 90 days.

### Fast path: revert traffic to the previous revision

```bash
# List recent revisions (most recent first).
gcloud run revisions list \
  --service=realreel-verifier \
  --region=us-central1 \
  --project=<verifier-project>

# Send 100% of traffic back to a specific known-good revision.
gcloud run services update-traffic realreel-verifier \
  --to-revisions=realreel-verifier-<known-good-revision>=100 \
  --region=us-central1 \
  --project=<verifier-project>
```

The new revision stays deployed but receives 0% traffic. Once the issue is understood, either fix-forward (new deploy on top) or repeat the command to shift traffic back. Validation: `curl https://<verifier>/healthz/ready` should return 200; structured logs should stop showing the failure pattern.

### Pre-rollback decision tree

| Symptom | Likely cause | Rollback fixes it? | Action |
|---|---|---|---|
| `/healthz/ready` returning 503 immediately after deploy | `DATABASE_URL` typo, `verifier_readonly` password rotated mid-deploy, or `lookup_signing_key_revocation` schema drift | Yes (env state is per-revision) | Roll back revision; fix env on next deploy |
| `VERIFIER_UNAVAILABLE` spike with `category:play-integrity` tag | IAM grant lost on the runtime SA, or `PLAY_INTEGRITY_*` env mistyped | Sometimes (rollback restores env values) | Roll back revision FIRST to stop the spike; then check IAM bindings + env values for the next attempt |
| `UNTRUSTED_ISSUER` for previously-accepted manifests | Image-baked trust anchor changed (someone rotated `verifier/trust-sources/<id>/root.pem` mid-deploy and bundled it into the new revision) | Yes (PEMs travel with the image) | Roll back revision — anchors revert with the image |
| Schema drift between verifier expectations and `media` table / `c2pa_manifest` column | Migration applied AFTER verifier read its types at build time | **No** (image-baked types vs DB-current state can't coexist) | Don't roll back — fix-forward by deploying a verifier matched to current DB state |
| `consume_and_record_attestation` RPC signature changed | Migration replaced RPC; verifier code expects old shape | **No** | Same — fix-forward only |
| Sentry showing a code-level bug we just shipped | New regression | Yes | Roll back revision; the code lives in the image |

### What rollback does NOT undo

| State | Why | What to do instead |
|---|---|---|
| **Database migrations** | Migrations are append-only and shared with the edge function. Rolling back the verifier image while migrations stay forward is a runtime contract break. | Apply a `down` migration explicitly (Supabase CLI), or fix-forward. |
| **Burned attestation nonces** | `consume_and_record_attestation` is a write; rolling back the verifier doesn't un-burn rows in `attestation_challenges`. | None — burns are correct by design. Users get a fresh nonce on next request. |
| **Already-inserted `media` rows** | Insert happens in the edge function on verifier OK. Rolling back the verifier doesn't roll back the row. | If the bad deploy let through manifests the new verifier would reject, run a sweep (manual SQL or a one-shot `revoke + remove` if a wrong-key cert slipped through). |
| **Sentry events** | Append-only by definition. | Annotate the affected event range with a comment so post-mortems are easier. |
| **Supabase Edge secrets** (`VERIFIER_URL`, `VERIFIER_SHARED_SECRET`) | Edge secrets are per-project, not per-revision. | If you rotated either as part of the bad deploy, restore them explicitly. |

### When rolling back is the wrong move

- **A new migration is in flight and the new verifier requires it.** Rolling back the verifier without rolling back the migration leaves the old verifier reading new-shape rows it doesn't understand. Same the other way. If you must roll back, roll back the migration first.
- **The trust list (`@realreel/c2pa-trust-core` package) was updated and the new verifier honors a new entry.** Rolling back drops that entry; manifests from the new vendor start failing `UNTRUSTED_ISSUER`. Pre-launch this is fine; post-launch consider whether you need to fix-forward instead.
- **A revoked-cert add was the goal of the deploy.** Rolling back un-revokes (DB state is independent, but the verifier image's expectations of revocation rows may differ). Re-deploy with the revocation logic intact.

For incidents that can't be rollback-fixed, the fix-forward path is: identify the bug → patch on `main` → run the standard Deploy flow above. The 5-minute `failureThreshold` startup probe on `/healthz/ready` is the safety net — a bad image fails the probe and Cloud Run keeps serving from the prior revision while you investigate.

## QA + dev testing against Play Integrity

Play Integrity returns `appRecognitionVerdict: UNRECOGNIZED_VERSION` for any APK whose signing cert isn't registered in Play Console — that includes locally-built debug APKs, EAS-signed APKs installed directly via `adb`, and anything that didn't ship through the Play Store. The verifier rejects these on `ATTESTATION_INVALID`.

To test the full strict-verifier flow on a real Android device:

1. Build a release-signed AAB: `eas build --platform android --profile preview` (or `production`).
2. Play Console → Testing → Internal testing → Create release → upload the AAB.
3. Play Console → Internal testing → Testers → add your Google account.
4. Install via the Play Store internal-test link on the device.

Internal-test installs get `PLAY_RECOGNIZED` because Google's the one delivering the APK. No further verifier change needed.

For everyday dev work that doesn't need real Play Integrity (iOS captures, JS-side logic, verifier unit tests), the local dev verifier runs in lenient mode (no `PLAY_INTEGRITY_*` env vars) and accepts unattested manifests — no Internal Testing setup required.

## Diagnostics: Play Integrity decode failures

When the verifier rejects an Android upload with a Play-Integrity-related error code, the underlying HTTP response from Google's `decodeIntegrityToken` API tells you where the problem is. The verifier maps Google's status codes to verifier error codes per the table below; this section is the bridge from "I see this Sentry tag" to "here's what's broken."

| Google status | Verifier `error_code` | Likely cause | Where to look |
|---|---|---|---|
| 200 OK | (success) | — | — |
| 400 Bad Request | `ATTESTATION_INVALID` | Token is malformed, expired beyond ~24h, or doesn't match the package name in the path. User-side issue (tampered build, stale token, or someone forwarding a token from a different app). | The token's `requestDetails.timestampMillis` and `requestPackageName` once decoded |
| 401 Unauthorized | `VERIFIER_UNAVAILABLE` | Bearer token in the request is invalid / expired. Our service account credentials problem. | `GoogleAuth` initialization, runtime SA on Cloud Run |
| 403 Forbidden | `VERIFIER_UNAVAILABLE` | SA exists but lacks `roles/playintegrity.user` on the Play Integrity project. Most common after a new deploy with no IAM grant, or after switching service accounts. | IAM bindings on the project specified by `PLAY_INTEGRITY_CLOUD_PROJECT_NUMBER` (Deploy step 3) |
| 404 Not Found | `VERIFIER_UNAVAILABLE` | Two flavors. (a) Wrong URL — `PLAY_INTEGRITY_PACKAGE_NAME` env doesn't match a real Play Console listing. (b) Project never got linked to the Play Console app (Play Console → App integrity → Play Integrity API). Both are setup bugs. | Env var value matches Play Console listing; project link is in place |
| 422 / other 4xx | `ATTESTATION_INVALID` | Token format issue. Sometimes seen if the token is decoded with mismatched cloud project (client and verifier disagree on `PLAY_INTEGRITY_CLOUD_PROJECT_NUMBER`). | Both sides agree on the project number; Android module's `CLOUD_PROJECT_NUMBER` const matches the verifier's env var |
| 5xx | `VERIFIER_UNAVAILABLE` | Google's side. Retryable. | Google's status page; should clear on its own |
| (timeout, 3s) | `VERIFIER_UNAVAILABLE` (message tagged "timeout") | Google didn't respond within 3 seconds. Could be regional Google degradation, or our Cloud Run egress is slow. | Cloud Run egress metrics; Google status page |
| (network error) | `VERIFIER_UNAVAILABLE` (message tagged "network error") | DNS failure, TCP reset, etc. before Google even responded. | Cloud Run egress connectivity |

**Quick triage rule of thumb:**
- `ATTESTATION_INVALID` on Android uploads → user-side issue, look at the token / device.
- `VERIFIER_UNAVAILABLE` from Android uploads → our-side issue, look at IAM grants, env vars, or Google's status page.

## Monitoring + alerts

Two alerts worth setting up (both manual via Sentry UI or your alerting tool — no code config today):

### 1. `VERIFIER_UNAVAILABLE` rate spike

**Why:** This error code fires for both Google API outages (retryable) AND our own config drift (IAM grant lost, env var typo, package name mismatch). A sustained spike means one of the two — either way, oncall should know within minutes.

**Suggested Sentry alert:**
- Filter: `error_code:VERIFIER_UNAVAILABLE AND category:play-integrity`
- Condition: rate > 10 events / 5 minutes (tune to your traffic; aim for "noticeable above baseline")
- Action: page on-call or post to a `#realreel-alerts` Slack channel

**Diagnostic playbook when this fires:**
1. Check the most recent event's `message` tag — look for "timeout" / "HTTP 401" / "HTTP 403" / "HTTP 404" / "HTTP 5xx" in the error text.
2. If 401/403/404 → use the Diagnostics table above to identify which of (auth, IAM, URL, project-link) is broken.
3. If 5xx or timeout → check Google's status page; if Google looks fine, check Cloud Run egress.
4. If the error message says HTTP 400 or 422 → this is the wrong error code, see alert #2.

### 2. `ATTESTATION_INVALID` rate spike

**Why:** This code fires when a real user's token gets rejected — tampered build, stale token, mismatched cloud project. A baseline rate is expected (some users will be on rooted devices, etc.); a spike usually means we broke something at the client side.

**Suggested Sentry alert:**
- Filter: `error_code:ATTESTATION_INVALID AND category:play-integrity`
- Condition: rate increase > 2× baseline over 1 hour
- Action: notify (don't necessarily page)

**Diagnostic playbook when this fires:**
1. Decode a sample token (Sentry events should have the token snippet in `extra`). Use Google's Play Integrity API replay UI or a quick local decode.
2. Check `requestDetails.requestPackageName` — does it match our env var?
3. Check `requestDetails.timestampMillis` — is it from a recent window or stale?
4. If the cloud project numbers between Android client (`CLOUD_PROJECT_NUMBER` const in PhotoAttestModule.kt) and verifier (`PLAY_INTEGRITY_CLOUD_PROJECT_NUMBER` env) disagree, this is the most common cause of a spike post-deploy.

### 3. `SIGNATURE_INVALID` rate spike

**Why:** This code fires from several places: the action allowlist (Stage 1 or Stage 2 carries a disallowed c2pa action), the fresh-capture rule (Stage 1 has ingredients), the parent-ingredient structure check, and the time-bound cert-validity gates (untrusted-TSA-chain, future-dated signature). A baseline rate is expected (malformed third-party content + occasional clock-skewed captures); a spike that correlates with messages mentioning `untrusted chain` is the meaningful signal that a TSA operator has had a cert revocation, an outage, or a trust-list drift since we last vendored the C2PA TSA Trust List.

Distinguish via the error `detail` substring:
- `untrusted chain` → the untrusted-TSA-chain gate, a TSA-trust problem (this is the operator concern).
- `in the future` → the future-dated-signature gate (usually a single rooted/clock-skewed device).
- `disallowed c2pa action` → action allowlist, content-side.
- Anything else → structural-rule violations covered elsewhere.

**Suggested Sentry alert (TSA-trust subset):**
- Filter: `error_code:SIGNATURE_INVALID AND message:"untrusted chain"`
- Condition: rate increase > 5× baseline over 1 hour, OR any sustained > 1 / minute
- Action: notify

**Diagnostic playbook when the `untrusted chain` filter fires:**
1. Pull a sample event's full detail string — it carries the TSA Responder DN, which tells you which TSA operator's chain failed.
2. Compare to `verifier/trust-sources/c2pa-tsa/c2pa-tsa-trust-list.pem`: was the failing TSA root present in our vendored list? Bump the snapshot if upstream's C2PA TSA Trust List has added a new root our pool is missing.
3. If the failing TSA is one of our own fetch URLs (DigiCert primary, SSL.com fallback), check the app's TSA client Sentry warnings on the client side — a fallback-engaged warning paired with an `untrusted chain` spike means the fallback TSA's root rotated; refresh `verifier/trust-sources/c2pa-tsa-fallback/`.

### 4. (Already covered) Play Integrity lenient-mode startup warning

The verifier emits a WARNING log at startup if `NODE_ENV=production` but `PLAY_INTEGRITY_*` env vars are unset. Set a Cloud Logging alert on `category="play-integrity" AND mode="lenient"` to catch deploys that forgot the config entirely.

<!-- Anchor "#trust-anchor-rotation" is referenced by
     verifier/scripts/audit-trust-anchors.ts. Renaming this heading
     requires updating that script. -->
## Trust-anchor rotation

When the [`audit-trust-anchors`](scripts/audit-trust-anchors.ts) script (run via
`make verify-trust-anchors`) reports a CRIT (or you receive a new root from a
vendor):

1. Drop the new PEM at `verifier/trust-sources/<id>/root.pem`.
2. If the cert subject CN changed, update `rootCommonName` for that `id` in `trust-core/src/trust-list/trusted-issuers.ts`. The `trust-list-lockstep` test asserts PEM-subject CN equals `rootCommonName` and fails CI if the two drift.
3. If the cert's surfaced issuer string changed (which c2pa-rs derives from the leaf cert and is rare for a root-only rotation), update `issuerMatch` for that `id` in the same file. Substring match — not the trust gate. The trust gate is `trust_anchors` chain validation by c2pa-node; `issuerMatch` runs only on already-trusted certs.
4. Locally: `make verify-trust-anchors` → exit 0 confirms the new anchor reads cleanly and is self-signed. Run `cd verifier && npx vitest run` to confirm the lockstep test passes against the new PEM.
5. Rebuild image, redeploy to Cloud Run. The trust bundle is image-baked — rotation = redeploy.
6. Close the open GitHub issue (`label: trust-anchors`).

Note: `trust-sources.yaml` no longer carries an `issuer_match` field. The cross-process trust metadata (`id`, `displayName`, `issuerMatch`, `rootCommonName`) lives in `@realreel/c2pa-trust-core`; the verifier's YAML now holds only the per-source server policy (`root_cert`, `verification_profile`).

**First real rotation rewrites this section as it happens** — these are sketches, not a proven playbook. Mirrors the pattern in RealReel's internal CA custody documentation § "Operational runbooks — deferred".

## Other rotations

- **`VERIFIER_SHARED_SECRET`**: update Cloud Run env + Supabase Edge secret to the same new value; rolling restart.
- **`verifier_readonly` password**: `ALTER USER` in Supabase, update `DATABASE_URL` on Cloud Run, restart.
- **`CRON_SECRET`** (orphan sweeper): update both Vault entries + the sweep-orphan-storage function secret to the same new value.
- **Play Integrity SA**: if rotating the Cloud Run runtime SA (e.g., switching from default Compute SA to a custom one), grant `roles/playintegrity.user` to the new SA on `PLAY_INTEGRITY_CLOUD_PROJECT_NUMBER` BEFORE updating the Cloud Run service-account, then revoke from the old SA AFTER traffic shifts.

Same caveat as trust-anchor rotation — first execution rewrites the relevant entry.
