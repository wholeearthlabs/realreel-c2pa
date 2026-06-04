# Verifier operations + rotations

Operate/troubleshoot runbook for the deployed verifier. For the deploy flow itself (env vars, bootstrap, build/push, GHCR image), see [DEPLOY.md](DEPLOY.md).

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

For incidents that can't be rollback-fixed, the fix-forward path is: identify the bug → patch on `main` → run the standard Deploy flow in [DEPLOY.md](DEPLOY.md). The 30-second startup probe on `/healthz/ready` (`failureThreshold: 6` × `periodSeconds: 5`) is the safety net — a bad image fails the probe and Cloud Run keeps serving from the prior revision while you investigate.

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
| 401 Unauthorized | `VERIFIER_UNAVAILABLE` | Bearer token in the request is invalid / expired. A service-account credentials problem. | `GoogleAuth` initialization, runtime SA on Cloud Run |
| 403 Forbidden | `VERIFIER_UNAVAILABLE` | SA exists but lacks `roles/playintegrity.user` on the Play Integrity project. Most common after a new deploy with no IAM grant, or after switching service accounts. | IAM bindings on the project specified by `PLAY_INTEGRITY_CLOUD_PROJECT_NUMBER` (Deploy step 3 in [DEPLOY.md](DEPLOY.md)) |
| 404 Not Found | `VERIFIER_UNAVAILABLE` | Two flavors. (a) Wrong URL — `PLAY_INTEGRITY_PACKAGE_NAME` env doesn't match a real Play Console listing. (b) Project never got linked to the Play Console app (Play Console → App integrity → Play Integrity API). Both are setup bugs. | Env var value matches Play Console listing; project link is in place |
| 422 / other 4xx | `ATTESTATION_INVALID` | Token format issue. Sometimes seen if the token is decoded with mismatched cloud project (client and verifier disagree on `PLAY_INTEGRITY_CLOUD_PROJECT_NUMBER`). | Both sides agree on the project number; Android module's `CLOUD_PROJECT_NUMBER` const matches the verifier's env var |
| 5xx | `VERIFIER_UNAVAILABLE` | Google's side. Retryable. | Google's status page; should clear on its own |
| (timeout, 3s) | `VERIFIER_UNAVAILABLE` (message tagged "timeout") | Google didn't respond within 3 seconds. Could be regional Google degradation, or slow Cloud Run egress. | Cloud Run egress metrics; Google status page |
| (network error) | `VERIFIER_UNAVAILABLE` (message tagged "network error") | DNS failure, TCP reset, etc. before Google even responded. | Cloud Run egress connectivity |

**Quick triage rule of thumb:**
- `ATTESTATION_INVALID` on Android uploads → user-side issue, look at the token / device.
- `VERIFIER_UNAVAILABLE` from Android uploads → a server-side issue: look at IAM grants, env vars, or Google's status page.

## Monitoring + alerts

Wire alerts through your own tooling — there's no in-code alert config. At minimum,
watch for sustained spikes in these structured `error_code`s:

- **`VERIFIER_UNAVAILABLE`** — a server-side problem (lost IAM grant, bad/expired SA
  credentials, `PLAY_INTEGRITY_*` typo) *or* a Google API outage. The Diagnostics
  table above maps the underlying Google HTTP status to the cause.
- **`ATTESTATION_INVALID`** (Android) — a client-side problem (tampered/stale token,
  mismatched cloud project). A low baseline is normal; a spike usually means a client
  regression.
- **`SIGNATURE_INVALID`** with an `untrusted chain` `detail` — a TSA trust-list drift
  (an operator rotated/revoked a root not in your vendored pool). See
  [Trust-anchor rotation](#trust-anchor-rotation).

The verifier also emits a startup WARNING (`category="play-integrity"`, `mode="lenient"`)
when `NODE_ENV=production` but `PLAY_INTEGRITY_*` is unset — alert on it to catch a
deploy that silently forgot the strict-mode config.

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

**First real rotation rewrites this section as it happens** — these are sketches, not a proven playbook.

## Other rotations

- **`VERIFIER_SHARED_SECRET`**: update Cloud Run env + Supabase Edge secret to the same new value; rolling restart.
- **`verifier_readonly` password**: `ALTER USER` in Supabase, update `DATABASE_URL` on Cloud Run, restart.
- **`CRON_SECRET`** (orphan sweeper): update both Vault entries + the sweep-orphan-storage function secret to the same new value.
- **Play Integrity SA**: if rotating the Cloud Run runtime SA (e.g., switching from default Compute SA to a custom one), grant `roles/playintegrity.user` to the new SA on `PLAY_INTEGRITY_CLOUD_PROJECT_NUMBER` BEFORE updating the Cloud Run service-account, then revoke from the old SA AFTER traffic shifts.

Same caveat as trust-anchor rotation — first execution rewrites the relevant entry.
