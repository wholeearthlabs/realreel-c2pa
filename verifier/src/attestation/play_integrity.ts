// Stage-2 Play Integrity assertion validator (Android).
//
// Sister of verifier/src/attestation/apple.ts. Enforces the Stage-2
// app-integrity gate described in TRUST_ARCHITECTURE.md on Android,
// closing the scaled-distribution attack (forked APK / mass replay of a
// tampered build).
//
// Enforced for every signed manifest carrying `org.realreel.play_integrity`:
//
//   1. Structural presence — assertion has well-formed { challenge, token,
//      platform: "android" } fields.
//   2. JWS decode + Google signature verification — done by Google's
//      decodeIntegrityToken server API. The returned plaintext verdict
//      payload is trustworthy iff the API call succeeded.
//   3. Verdict enforcement — appRecognitionVerdict == PLAY_RECOGNIZED
//      AND deviceRecognitionVerdict contains MEETS_STRONG_INTEGRITY.
//   4. Single-use challenge consumption — atomic UPDATE in the verifier's
//      DB burns the server-issued nonce, so a captured-and-republished
//      manifest fails the second redemption.
//
// Unlike iOS App Attest (where Apple's signature is verified locally against
// an enrollment-stored credCert pubkey), Android verdicts are forgeable JSON
// claims if Google's signature is unchecked. So this validator does FULL JWS
// verification via Google's decodeIntegrityToken API — there is no
// structural-only fallback path.
//
// Deferred (defense-in-depth only): a requestHash binding check —
// confirming the JWS payload's
// `tokenPayloadExternal.requestDetails.requestHash` equals
// base64url(SHA256(challenge || signing_leaf_SPKI)). The Android module
// already produces this binding device-side; the verifier can't reconstruct
// it because c2pa-node v0.5.5 doesn't expose the leaf cert's SPKI bytes.
// Defended by the nonce burn alone for now — a token issued for device A's
// SPKI can't be replayed against device B's manifest because the (key_id,
// nonce) consume RPC binds the nonce to device A's signing key.

import { GoogleAuth } from "google-auth-library";

import { postgresAdapter } from "../db.js";
import type { NonceBurner } from "../ports.js";
import { VerifyError, VerifyErrorCode } from "../errors.js";
import type { PlayIntegrityConfig } from "../config.js";
import type { AssertionShape, ManifestShape } from "../c2pa-shape.js";

// Single source of truth lives in @realreel/c2pa-trust-core; re-exported
// here so existing call sites keep working unchanged.
import { PLAY_INTEGRITY_LABEL } from "@realreel/c2pa-trust-core";
export { PLAY_INTEGRITY_LABEL };

// All VerifyErrors thrown from this file carry `category: 'play-integrity'`
// so server-side Sentry alerts can filter on Android-specific failures
// (e.g., `category:play-integrity AND error_code:VERIFIER_UNAVAILABLE`).
// See verifier/OPERATIONS.md § "Monitoring + alerts" for the alert spec.
function piVerifyError(code: VerifyErrorCode, detail: string): VerifyError {
  return new VerifyError(code, detail, { category: "play-integrity" });
}

/**
 * Shape of the org.realreel.play_integrity assertion data emitted by
 * native/android/.../PhotoAttestModule.kt's
 * playIntegrityAssertionEntry helper.
 */
export interface PlayIntegrityAssertionData {
  challenge: string;
  token: string;
  platform: string;
}

/**
 * Plaintext payload returned by Google's decodeIntegrityToken server API.
 * https://developer.android.com/google/play/integrity/standard
 *
 * We type only the fields we read; Google may add more — extra fields
 * pass through harmlessly. (Strict-shape parsing would couple us to
 * Google's schema unnecessarily.)
 */
export interface PlayIntegrityDecodedPayload {
  tokenPayloadExternal?: {
    requestDetails?: {
      requestPackageName?: string;
      timestampMillis?: string;
      requestHash?: string;
    };
    appIntegrity?: {
      appRecognitionVerdict?: string;
      packageName?: string;
      versionCode?: string;
    };
    deviceIntegrity?: {
      deviceRecognitionVerdict?: string[];
      // Optional device labels (enabled per Play Console → App integrity →
      // Play Integrity API → Response settings). Required for the Android
      // SDK gate below. Per Google's docs, deviceAttributes is nested INSIDE
      // deviceIntegrity (NOT a sibling of it):
      // https://developer.android.com/google/play/integrity/verdicts
      // If absent in the decoded payload, the verifier rejects fail-closed.
      deviceAttributes?: {
        sdkVersion?: number;
      };
    };
    accountDetails?: {
      appLicensingVerdict?: string;
    };
  };
}

// Minimum Android API level (SDK_INT) we accept when MEETS_STRONG_INTEGRITY
// is the device verdict. Google's STRONG verdict carries different semantics
// across versions:
//   * Android 13+ (API 33+): STRONG requires both DEVICE integrity and
//     security updates within the last year on all partitions.
//   * Android 12 and lower (API <= 32): STRONG requires only hardware-backed
//     proof of boot integrity — NO patch-currency component.
// We require API 33 so the doc-stated property "STRONG transitively
// enforces patch currency within ~1 year" holds universally. Devices on
// API <= 32 are rejected even with a STRONG verdict; the enrollment
// patch-level gate already filtered first-enrollment for those devices,
// but Stage 2 needs an upload-time bar too. Source:
// https://developer.android.com/google/play/integrity/verdicts
const MIN_SDK_VERSION_FOR_STRONG = 33;

// Allowed clock-skew between Google's `timestampMillis` claim (token mint
// time) and our receive time. Generous (30 min) because legitimate flows are
// bounded by upload latency, not round-trip — a large video on bad cellular
// can take tens of minutes to upload after Stage 2 signs.
//
// The window can be loose because it isn't the primary replay defense: a
// replay needs the hardware-backed signing key the token is bound to (via
// requestHash = SHA256(challenge||SPKI), non-extractable in StrongBox/TEE),
// c2pa-rs content-hash binding blocks swapping content into someone else's
// manifest, and the nonce is keyed to (signing_key_id, nonce) so an attacker
// can't mint one against another user's key.
const TOKEN_FRESHNESS_WINDOW_MS = 30 * 60 * 1000;

// Hard timeout on the Google decode call so a hanging API call doesn't pin a
// Cloud Run worker until the platform's much-longer outer request timeout.
// AbortSignal.timeout fires a DOMException("TimeoutError") which the fetch
// catch block maps to VERIFIER_UNAVAILABLE (retryable).
const DECODE_TIMEOUT_MS = 3_000;

// Google's documented scope for Play Integrity API calls. The GoogleAuth
// client fetches an access token bound to this scope; the access token is
// then sent as `Authorization: Bearer <...>` to decodeIntegrityToken.
const PLAY_INTEGRITY_OAUTH_SCOPE =
  "https://www.googleapis.com/auth/playintegrity";

// Lazy singleton — credential discovery (Application Default Credentials)
// hits filesystem + metadata server, amortized across requests by reusing
// the client for the process lifetime.
let cachedAuthClient: GoogleAuth | null = null;
function getAuthClient(): GoogleAuth {
  if (cachedAuthClient !== null) return cachedAuthClient;
  cachedAuthClient = new GoogleAuth({ scopes: PLAY_INTEGRITY_OAUTH_SCOPE });
  return cachedAuthClient;
}

/**
 * True iff the manifest carries an org.realreel.play_integrity assertion.
 * Used by the realreel profile's envelope dispatch — in lenient dev mode
 * the envelope is validated when present and tolerated when absent; in
 * required mode an absent envelope is a hard reject.
 */
export function hasPlayIntegrityAssertion(manifest: ManifestShape): boolean {
  return (manifest.assertions ?? []).some(
    (a: AssertionShape) => a.label === PLAY_INTEGRITY_LABEL,
  );
}

/**
 * Find and structurally validate the play_integrity assertion on a single
 * manifest stage. Throws VerifyError if missing or malformed; returns the
 * parsed envelope otherwise. Split from token consumption so the profile can
 * validate structure before any Google/DB side effect or nonce burn.
 */
export function validatePlayIntegrityStructure(
  manifest: ManifestShape,
  stageLabel: string,
): PlayIntegrityAssertionData {
  const found = (manifest.assertions ?? []).find(
    (a: AssertionShape) => a.label === PLAY_INTEGRITY_LABEL,
  );
  if (!found) {
    throw piVerifyError(
      VerifyErrorCode.ATTESTATION_MISSING,
      `${stageLabel} manifest lacks ${PLAY_INTEGRITY_LABEL} assertion`,
    );
  }
  const data = found.data as Partial<PlayIntegrityAssertionData> | undefined;
  if (
    !data ||
    typeof data.challenge !== "string" ||
    typeof data.token !== "string" ||
    typeof data.platform !== "string"
  ) {
    throw piVerifyError(
      VerifyErrorCode.ATTESTATION_INVALID,
      `${stageLabel} ${PLAY_INTEGRITY_LABEL} is malformed`,
    );
  }
  if (data.platform !== "android") {
    throw piVerifyError(
      VerifyErrorCode.ATTESTATION_INVALID,
      `${stageLabel} ${PLAY_INTEGRITY_LABEL} platform must be 'android' (got '${data.platform}')`,
    );
  }
  // The token is an opaque string from Google's Standard Integrity API
  // (StandardIntegrityTokenProvider.request().token()), submitted verbatim to
  // decodeIntegrityToken. GOTCHA: it is NOT JWS compact serialization — the
  // Standard API returns a single base64url blob with no dot separators, so
  // any `split(".").length === 3` check would reject every real upload. Only
  // Google's decodeIntegrityToken can authoritatively validate it; here we
  // just bound it as a plausible token string (length + base64url alphabet)
  // and let the consume path surface a real rejection as ATTESTATION_INVALID.
  if (
    data.token.length < MIN_TOKEN_LENGTH ||
    data.token.length > MAX_TOKEN_LENGTH ||
    !isPlausibleTokenAlphabet(data.token)
  ) {
    throw piVerifyError(
      VerifyErrorCode.ATTESTATION_INVALID,
      `${stageLabel} ${PLAY_INTEGRITY_LABEL} token failed plausibility check (length=${data.token.length})`,
    );
  }
  if (!isBase64(data.challenge)) {
    throw piVerifyError(
      VerifyErrorCode.ATTESTATION_INVALID,
      `${stageLabel} ${PLAY_INTEGRITY_LABEL} challenge is not base64`,
    );
  }
  return data as PlayIntegrityAssertionData;
}

/** Observed Standard Integrity tokens run 500–3000+ chars; bounds are a
 *  conservative floor + a generous ceiling against adversarial inputs
 *  (Google doesn't document either bound). */
const MIN_TOKEN_LENGTH = 300;
const MAX_TOKEN_LENGTH = 16384;

function isPlausibleTokenAlphabet(value: string): boolean {
  // base64url (RFC 4648 §5) plus `.` in case Google ever ships a JWS/JWE
  // compact form. No padding chars, no whitespace, no `+` / `/`.
  return /^[A-Za-z0-9_.-]+$/.test(value);
}

function isBase64(value: string): boolean {
  if (value.length === 0) return false;
  return /^[A-Za-z0-9+/=_-]+$/.test(value);
}

/**
 * Full JWS decode + verdict enforcement + atomic nonce consumption for
 * a pre-validated Play Integrity envelope. Wraps:
 *
 *   1. Google decodeIntegrityToken API call (verifies the JWS signature
 *      server-side, returns plaintext verdicts).
 *   2. Package-name / verdict / freshness checks on the decoded payload.
 *   3. consumeAndRecordAttestation RPC to burn the nonce single-use.
 *
 * Stage label is threaded through for legible error messages — a single
 * verifier pass validates Stage 1 then Stage 2 and the messages need to
 * tell them apart.
 */
export async function consumePlayIntegrityForStage(
  envelope: PlayIntegrityAssertionData,
  signingKeyId: string,
  stageLabel: string,
  config: PlayIntegrityConfig | undefined,
  nonceBurner: NonceBurner = postgresAdapter,
): Promise<void> {
  await verifyPlayIntegrityToken(envelope, stageLabel, config);
  await consumeNonce(envelope.challenge, signingKeyId, stageLabel, nonceBurner);
}

/**
 * Verify-only Play Integrity path: decode + verdict-enforce, no nonce burn.
 * Symmetric with apple.ts `verifyAppAttestAssertion`.
 */
export async function verifyPlayIntegrityToken(
  envelope: PlayIntegrityAssertionData,
  stageLabel: string,
  config: PlayIntegrityConfig | undefined,
): Promise<void> {
  if (!config) {
    // Reachable only in the lenient (dev / local-verifier) mode where
    // attestationRequired is false. Production sets ATTESTATION_REQUIRED=true,
    // which requires the PLAY_INTEGRITY_* env vars. Accept the structural
    // envelope; there's nothing else to validate without config.
    return;
  }
  const payload = await decodeIntegrityToken(envelope.token, config);
  enforceVerdicts(payload, config, stageLabel);
}

/**
 * Call Google's decodeIntegrityToken server API. Returns the parsed
 * plaintext payload (containing verdicts) iff the JWS signature checks
 * out. Network failures bubble up as VERIFIER_UNAVAILABLE; 4xx responses
 * from Google indicate a tampered or malformed token and are mapped to
 * ATTESTATION_INVALID.
 *
 * Doc: https://developer.android.com/google/play/integrity/standard#decrypt-verify-server
 *
 * Alternative: offline JWS verification against Google's published JWKS
 * (plus per-project JWE decryption via a Response Decryption Key) avoids the
 * per-upload network call and quota at the cost of JWKS/RDK management. The
 * swap is contained to this function body.
 */
async function decodeIntegrityToken(
  token: string,
  config: PlayIntegrityConfig,
): Promise<PlayIntegrityDecodedPayload> {
  const url = `https://playintegrity.googleapis.com/v1/${encodeURIComponent(config.packageName)}:decodeIntegrityToken`;
  let accessToken: string | null;
  try {
    const client = getAuthClient();
    accessToken = (await client.getAccessToken()) ?? null;
  } catch (e) {
    throw piVerifyError(
      VerifyErrorCode.VERIFIER_UNAVAILABLE,
      `Play Integrity auth token failed: ${(e as Error).message ?? "(no message)"}`,
    );
  }
  if (!accessToken) {
    throw piVerifyError(
      VerifyErrorCode.VERIFIER_UNAVAILABLE,
      "Play Integrity auth returned empty access token",
    );
  }
  let response: Response;
  try {
    response = await fetch(url, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${accessToken}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ integrity_token: token }),
      signal: AbortSignal.timeout(DECODE_TIMEOUT_MS),
    });
  } catch (e) {
    // AbortSignal.timeout surfaces as a DOMException with name "TimeoutError"
    // (Node 22+). undici may wrap it; we cover both paths via a name check
    // and a message-substring fallback so a future runtime swap doesn't
    // silently regress the timeout-mapping behavior. Both timeouts and
    // generic network errors are retryable from the caller's perspective —
    // same VERIFIER_UNAVAILABLE bucket, distinguishable in logs via the
    // appended message.
    const err = e as Error & { name?: string };
    const isTimeout =
      err?.name === "TimeoutError" ||
      err?.name === "AbortError" ||
      err?.message?.includes("aborted") ||
      err?.message?.includes("timeout");
    const reason = isTimeout
      ? `timeout after ${DECODE_TIMEOUT_MS}ms`
      : `network error: ${err.message ?? "(no message)"}`;
    throw piVerifyError(
      VerifyErrorCode.VERIFIER_UNAVAILABLE,
      `Play Integrity decode ${reason}`,
    );
  }
  if (!response.ok) {
    // 401/403 → our auth is misconfigured (5xx-like from our perspective).
    // 400/404 → Google rejected the token bytes (4xx — token problem).
    // 5xx     → Google's side is down — retryable.
    const isOurFault =
      response.status === 401 ||
      response.status === 403 ||
      response.status === 404;
    const code =
      response.status >= 500 || isOurFault
        ? VerifyErrorCode.VERIFIER_UNAVAILABLE
        : VerifyErrorCode.ATTESTATION_INVALID;
    // Read the body for stderr only — do NOT embed it in VerifyError.detail.
    // detail is forwarded into the client-visible 422 response and Sentry,
    // and Google's decodeIntegrityToken error bodies have historically echoed
    // submitted token bytes. Keeping the body off the wire avoids leaking
    // those while still capturing it in Cloud Run logs for ops.
    try {
      const body = await response.text();
      console.warn(
        `[play_integrity] decode HTTP ${response.status}: ${truncate(body, 400)}`,
      );
    } catch {
      // ignore — body is informational only
    }
    throw piVerifyError(
      code,
      `Play Integrity decode rejected (HTTP ${response.status})`,
    );
  }
  let parsed: unknown;
  try {
    parsed = await response.json();
  } catch (e) {
    throw piVerifyError(
      VerifyErrorCode.VERIFIER_UNAVAILABLE,
      `Play Integrity decode returned non-JSON: ${(e as Error).message ?? "(no message)"}`,
    );
  }
  return parsed as PlayIntegrityDecodedPayload;
}

function truncate(s: string, max: number): string {
  if (s.length <= max) return s;
  return s.slice(0, max) + "…";
}

/**
 * Enforce the verdict gates RealReel requires for an Android upload.
 *
 *   * appRecognitionVerdict == PLAY_RECOGNIZED — Google sees an installed
 *     APK matching one of our published signing certs in Play Console.
 *     Catches forked-APK redistribution.
 *   * deviceIntegrity.deviceRecognitionVerdict includes MEETS_STRONG_INTEGRITY —
 *     hardware-backed integrity that resists leaked-keybox spoofing and (on
 *     Android 13+) transitively enforces a recent security patch. Requiring
 *     STRONG strictly narrows what passes vs. DEVICE (rooted phones /
 *     emulators fail either). iOS App Attest has no equivalent device/
 *     jailbreak verdict.
 *   * deviceIntegrity.deviceAttributes.sdkVersion >= 33 — Android 13+ only.
 *     On Android 12 and lower, STRONG carries no patch-currency component
 *     (Google docs), so we refuse to honor STRONG on those devices.
 *     Fail-closed: missing deviceAttributes / sdkVersion → reject (Play
 *     Console must have Optional device labels enabled in the response
 *     settings — see DEPLOY.md).
 *   * requestPackageName matches our configured package name — defends
 *     against a token forwarded from a different app's project.
 *   * timestampMillis within the freshness window — defense-in-depth
 *     against very-old tokens (the nonce burn is the primary defense).
 */
function enforceVerdicts(
  payload: PlayIntegrityDecodedPayload,
  config: PlayIntegrityConfig,
  stageLabel: string,
): void {
  const ext = payload.tokenPayloadExternal;
  if (!ext) {
    throw piVerifyError(
      VerifyErrorCode.ATTESTATION_INVALID,
      `${stageLabel} Play Integrity payload missing tokenPayloadExternal`,
    );
  }

  const reqPkg = ext.requestDetails?.requestPackageName;
  if (reqPkg !== config.packageName) {
    throw piVerifyError(
      VerifyErrorCode.ATTESTATION_INVALID,
      `${stageLabel} Play Integrity requestPackageName mismatch (got '${reqPkg ?? "(missing)"}', want '${config.packageName}')`,
    );
  }

  const appVerdict = ext.appIntegrity?.appRecognitionVerdict;
  if (appVerdict !== "PLAY_RECOGNIZED") {
    throw piVerifyError(
      VerifyErrorCode.ATTESTATION_INVALID,
      `${stageLabel} Play Integrity appRecognitionVerdict is '${appVerdict ?? "(missing)"}', want 'PLAY_RECOGNIZED'`,
    );
  }

  const deviceVerdicts = ext.deviceIntegrity?.deviceRecognitionVerdict ?? [];
  if (!deviceVerdicts.includes("MEETS_STRONG_INTEGRITY")) {
    throw piVerifyError(
      VerifyErrorCode.ATTESTATION_INVALID,
      `${stageLabel} Play Integrity deviceRecognitionVerdict lacks MEETS_STRONG_INTEGRITY (got [${deviceVerdicts.join(",") || "(empty)"}])`,
    );
  }

  // Android 12-and-lower compensating control: on those devices STRONG
  // does NOT include a patch-currency check (Google docs). Require
  // sdkVersion >= 33 so "STRONG implies recent patches" holds across all
  // accepted devices. Fail-closed on missing sdkVersion — if Play Console
  // doesn't have Optional device labels enabled, every Android upload
  // fails loudly here and ops fixes config, rather than the gate silently
  // passing stale-firmware devices.
  const sdkVersion = ext.deviceIntegrity?.deviceAttributes?.sdkVersion;
  if (typeof sdkVersion !== "number" || !Number.isFinite(sdkVersion)) {
    throw piVerifyError(
      VerifyErrorCode.ATTESTATION_INVALID,
      `${stageLabel} Play Integrity deviceAttributes.sdkVersion missing or non-numeric — Play Console Optional device labels must be enabled`,
    );
  }
  if (sdkVersion < MIN_SDK_VERSION_FOR_STRONG) {
    throw piVerifyError(
      VerifyErrorCode.ATTESTATION_INVALID,
      `${stageLabel} Play Integrity sdkVersion ${sdkVersion} below minimum ${MIN_SDK_VERSION_FOR_STRONG} (Android 13+); STRONG on Android <=12 carries no patch-currency guarantee`,
    );
  }

  const ts = ext.requestDetails?.timestampMillis;
  const tsMs = typeof ts === "string" ? Number(ts) : NaN;
  if (!Number.isFinite(tsMs)) {
    throw piVerifyError(
      VerifyErrorCode.ATTESTATION_INVALID,
      `${stageLabel} Play Integrity timestampMillis missing or non-numeric`,
    );
  }
  const skewMs = Math.abs(Date.now() - tsMs);
  if (skewMs > TOKEN_FRESHNESS_WINDOW_MS) {
    throw piVerifyError(
      VerifyErrorCode.ATTESTATION_INVALID,
      `${stageLabel} Play Integrity token too old (clock skew ${Math.round(skewMs / 1000)}s; window ${Math.round(TOKEN_FRESHNESS_WINDOW_MS / 1000)}s)`,
    );
  }
}

async function consumeNonce(
  challenge: string,
  signingKeyId: string,
  stageLabel: string,
  nonceBurner: NonceBurner,
): Promise<void> {
  try {
    await nonceBurner.burn(signingKeyId, challenge);
  } catch (e) {
    const msg = (e as Error).message ?? "";
    if (msg.includes("attestation_challenge_unavailable")) {
      throw piVerifyError(
        VerifyErrorCode.ATTESTATION_REPLAY,
        `${stageLabel} ${msg}`,
      );
    }
    throw e;
  }
}

// Re-export for tests.
export { decodeIntegrityToken, enforceVerdicts, consumeNonce };

// Test-only: reset the cached GoogleAuth client so a fresh mock can be
// installed between vitest cases. Not exported in the public production
// path — there's no reason to ever swap auth clients at runtime.
export function __resetAuthClientForTests(): void {
  cachedAuthClient = null;
}

