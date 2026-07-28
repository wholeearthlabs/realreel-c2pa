// Validates a hardware-attestation blob + PKCS#10 CSR, issues a CA-signed leaf
// for the device's signing key via the KMS-resident RealReel intermediate, and
// persists the (public key, attestation, leaf chain) tuple to user_signing_keys.
// JWT-required.
//
// Flow:
//   1. Resolve calling user via JWT.
//   2. Atomically burn the enrollment challenge via consume_enrollment_challenge RPC.
//   3. Validate platform.
//   4. Parse the CSR, verify its self-signature (possession proof), and
//      constant-time-compare its SPKI against the attested SE/StrongBox pubkey.
//   5. Branch on platform → call validateAppleAttestation or validateAndroidAttestation.
//   6. Build the leaf TBSCertificate, hash it, ask Cloud KMS to sign it with
//      the RealReel intermediate key, assemble `leaf + intermediate` PEM.
//   7. Call register_user_signing_key RPC (plain INSERT — see Notes below).
//   8. Return 200 with { ok, leafChainPEM } on success. Generic 400 on
//      validation failure (no internal leakage); 500 on issuance failure.
//
// Notes:
//   * Multi-device support: each enrollment INSERTs a new row. Multiple active
//     rows can coexist for the same (user_id, key_version) — one per device.
//   * Revocation is handled by the revoke-signing-key edge function. Orphaned
//     rows from device wipes are harmless because no client can produce a
//     valid signature for their public key.
//   * Re-enroll: callers pass body.supersedeKeyId = priorKeyId so the RPC
//     sets superseded_at on the prior row in the same INSERT transaction.
//     The Devices SELECT filters superseded rows out of the list while the
//     verifier still accepts them for pending uploads.
//   * The client persists the returned leafChainPEM and passes it to
//     signC2PACapture / signC2PAUpload on every sign. The verifier
//     microservice chain-validates it against the published RealReel root.
//   * The response includes the canonical keyId (sha256 of the SE/StrongBox
//     pubkey, base64) so the client can cache it locally. The Devices screen
//     uses this cached value to flag the "This device" row.

import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { handlePreflight, jsonResponse } from "../_shared/cors.ts";
import {
  getUserFromAuthHeader,
  makeServiceRoleClient,
  requireAal2IfMfaEnrolled,
} from "../_shared/auth.ts";
import { enforceRateLimit } from "../_shared/rate_limit.ts";
import { validateAppleAttestation } from "../_shared/attestation/apple.ts";
import { validateAndroidAttestation } from "../_shared/attestation/android.ts";
import {
  AttestationError,
  base64ToBytes,
  bytesToBase64,
  caHierarchy,
  ctEqual,
  extractCSRSpkiDer,
  extractSpkiDer,
  issueLeafChainFromCSR,
  parseCertFromPem,
  parseCSRFromPem,
  resolveV2LeafOptions,
  verifyCSRSignature,
} from "../_shared/attestation/pki.ts";
import type {
  AssuranceLevel,
  CaHierarchy,
  LeafPlatform,
} from "../_shared/attestation/pki.ts";
import type { KmsCredentials } from "../_shared/kms.ts";
import {
  KMS_EXPECTED_ALGORITHM,
  KMS_EXPECTED_ALGORITHM_V2,
  kmsGetPublicKey,
  kmsSignDigest,
  loadKmsCredentials,
} from "../_shared/kms.ts";
import {
  ANDROID_MIN_PATCH_LOOKBACK_MONTHS,
  ANDROID_PACKAGE_NAME,
  APPLE_APP_ID,
  MAX_SIGNING_KEY_ID_CHARS,
  REQUIRE_PRODUCTION_APPATTEST,
} from "../_shared/config.ts";

// Leaf validity. Short because TSA timestamping keeps a capture stamped
// before its leaf expires verifiable past expiry, so a short leaf no longer
// caps the offline-upload window. Buys rolling patch-currency (stale devices
// age off) + a revocation TTL; healthy devices silently re-enroll ~30 days
// before expiry via a non-destructive key rotation (the app's enrollment
// client).
//
// v1 issues a flat 180 days. v2 validity is per-platform/per-AL — CP §7.1.2
// caps AL2 leaves at 90 days and AL1 at 366.
//
// No verifier-side sync needed: the verifier's time gate reads each leaf's
// actual issued_at/expires_at from the issued_certificates ledger
// (checkLedgerTimeBounds in verifier/src/cert-validity.ts), so changing a
// lifetime here propagates through the ledger rows automatically.
export function leafValidityDays(
  hierarchy: CaHierarchy,
  platform: LeafPlatform,
  assuranceLevel: AssuranceLevel,
): number {
  if (hierarchy === "v1") return 180;
  return platform === "android" && assuranceLevel === "AL2" ? 90 : 180;
}

/**
 * Test-injection seams — production wires `defaultDeps`, tests inject mocks
 * via `handleRegister(req, customDeps)`. Large because the handler
 * orchestrates auth + CSR + attestation + KMS + persist, each needing an
 * injection point for error-path coverage.
 */
export interface RegisterDeps {
  getUserFromAuthHeader: typeof getUserFromAuthHeader;
  requireAal2IfMfaEnrolled: typeof requireAal2IfMfaEnrolled;
  enforceRateLimit: typeof enforceRateLimit;
  makeServiceRoleClient: typeof makeServiceRoleClient;
  validateAppleAttestation: typeof validateAppleAttestation;
  validateAndroidAttestation: typeof validateAndroidAttestation;
  parseCSRFromPem: typeof parseCSRFromPem;
  verifyCSRSignature: typeof verifyCSRSignature;
  extractCSRSpkiDer: typeof extractCSRSpkiDer;
  issueLeafChainFromCSR: typeof issueLeafChainFromCSR;
  loadKmsCredentials: typeof loadKmsCredentials;
  kmsSignDigest: typeof kmsSignDigest;
  /** Reads REALREEL_INTERMEDIATE_CERT_PEM. Injectable so tests can swap
   *  in a known-good PEM (or empty for the env-missing case) without
   *  process-wide Deno.env mutation. Called once per request. */
  getIntermediatePem: () => string;
  /** Confirms the configured intermediate cert matches the KMS public key
   *  AND that KMS is using the expected algorithm. defaultDeps wraps this
   *  in a per-instance cache so production pays the KMS round-trip once
   *  per cold start; tests inject uncached fakes that resolve immediately
   *  on happy paths or throw AttestationError on misconfig cases. */
  ensureIntermediateMatchesKms: (
    creds: KmsCredentials,
    intermediatePem: string,
  ) => Promise<void>;
}

/**
 * Internal helper: build a cached implementation of the intermediate↔KMS
 * consistency check from the underlying primitives. Stays a free function
 * (rather than a method on RegisterDeps) so it can be reused by tests
 * that want the caching behavior alongside their own KMS / cert fakes.
 *
 * The cache is a closure over `cache: Promise<void> | null`. Once resolved,
 * subsequent calls return the same promise — no re-fetching the KMS public
 * key on every request. Transient errors (KMS unreachable) null the cache
 * so the next request retries; permanent errors (KMS_INTERMEDIATE_MISMATCH,
 * KMS_ALGORITHM_MISMATCH) also null the cache so a fix-and-retry without
 * a process restart works.
 */
export function buildCachedIntermediateCheck(deps: {
  kmsGetPublicKey: typeof kmsGetPublicKey;
  parseCertFromPem: typeof parseCertFromPem;
  extractSpkiDer: typeof extractSpkiDer;
}): RegisterDeps["ensureIntermediateMatchesKms"] {
  let cache: Promise<void> | null = null;
  return (creds: KmsCredentials, intermediatePem: string): Promise<void> => {
    if (cache) return cache;
    cache = (async () => {
      let kmsPublicKey;
      try {
        kmsPublicKey = await deps.kmsGetPublicKey(creds);
      } catch (e) {
        // Don't cache transient KMS errors — the next request retries.
        cache = null;
        throw e;
      }
      // Algorithm gate: the leaf's declared signatureAlgorithm tracks the
      // active hierarchy (v1 → ecdsaWithSHA256 / P-256 intermediate, v2 →
      // ecdsaWithSHA384 / P-384 claim ICA). KMS signing with any other
      // algorithm produces leaves whose declared signatureAlgorithm lies.
      // Fail-fast at cold start so a misconfigured GCP_KMS_KEY_RESOURCE —
      // including a hierarchy flip that swapped only one of the paired env
      // vars — can never mint a single bad cert.
      let expectedAlgorithm: string;
      try {
        expectedAlgorithm = caHierarchy() === "v2"
          ? KMS_EXPECTED_ALGORITHM_V2
          : KMS_EXPECTED_ALGORITHM;
      } catch (e) {
        // A junk CA_HIERARCHY is a fixable misconfig like the two below —
        // don't pin a rejected promise in the cache for the isolate's life.
        cache = null;
        throw e;
      }
      if (kmsPublicKey.algorithm !== expectedAlgorithm) {
        cache = null;
        throw new AttestationError(
          "KMS_ALGORITHM_MISMATCH",
          `Cloud KMS algorithm is ${kmsPublicKey.algorithm}, expected ${expectedAlgorithm} — ` +
            "GCP_KMS_KEY_RESOURCE and CA_HIERARCHY are out of sync. " +
            "Repoint at the matching key version.",
        );
      }
      let intCert;
      try {
        intCert = deps.parseCertFromPem(intermediatePem);
      } catch (e) {
        cache = null;
        throw new AttestationError(
          "INTERMEDIATE_PARSE_FAILED",
          `Could not parse REALREEL_INTERMEDIATE_CERT_PEM: ${
            (e as Error).message
          }`,
        );
      }
      const intSpki = deps.extractSpkiDer(intCert);
      if (!ctEqual(kmsPublicKey.spki, intSpki)) {
        cache = null;
        throw new AttestationError(
          "KMS_INTERMEDIATE_MISMATCH",
          "REALREEL_INTERMEDIATE_CERT_PEM does not match Cloud KMS public key — " +
            "GCP_KMS_KEY_RESOURCE and REALREEL_INTERMEDIATE_CERT_PEM are out of sync. " +
            "Check both Supabase secrets.",
        );
      }
    })();
    return cache;
  };
}

export const defaultDeps: RegisterDeps = {
  getUserFromAuthHeader,
  requireAal2IfMfaEnrolled,
  enforceRateLimit,
  makeServiceRoleClient,
  validateAppleAttestation,
  validateAndroidAttestation,
  parseCSRFromPem,
  verifyCSRSignature,
  extractCSRSpkiDer,
  issueLeafChainFromCSR,
  loadKmsCredentials,
  kmsSignDigest,
  getIntermediatePem: () => Deno.env.get("REALREEL_INTERMEDIATE_CERT_PEM") ?? "",
  ensureIntermediateMatchesKms: buildCachedIntermediateCheck({
    kmsGetPublicKey,
    parseCertFromPem,
    extractSpkiDer,
  }),
};

// Per-user rate limits. Enrollment is rare (once per device per install) so
// limits can be tight without hurting legitimate use. Attackers spamming
// register-signing-key (e.g. with stolen JWTs) are cut off quickly.
const RATE_LIMIT_WINDOWS = [
  { windowSec: 3600, max: 5 },     // 5 enrollments / hour
  { windowSec: 86400, max: 20 },   // 20 enrollments / day
] as const;

const ALLOWED_PLATFORMS = ["ios", "android-strongbox", "android-tee"] as const;
type Platform = typeof ALLOWED_PLATFORMS[number];

interface RegisterBody {
  publicKey?: string;
  platform?: Platform;
  attestation?: string;
  keyId?: string;
  keyVersion?: string;
  challenge?: string;
  csr?: string;
  // Optional human-readable device label populated client-side from
  // expo-device's osName + osVersion (e.g. "iOS 18.2"). Never PII — the client
  // must NOT send Device.deviceName ("Dan's iPhone"). Omitted → persist NULL.
  deviceLabel?: string;
  // Optional. When present, the canonical key_id of the user's prior row that
  // this enrollment replaces. The RPC sets superseded_at on that row in the
  // same transaction as the INSERT. Cross-user supersede is structurally
  // prevented by the user_id guard inside the RPC. Used by the Devices
  // re-enroll and auto-rotate-near-expiry flows.
  supersedeKeyId?: string;
}

// (MAX_SIGNING_KEY_ID_CHARS comes from ../_shared/config.ts so this bound
// stays in lockstep with revoke-signing-key's keyId validation.)

// Bounded server-side. The client emits ~15-20 chars; 64 leaves margin
// without enabling abuse vectors via large bodies. An over-long label is
// TRUNCATED to this many chars (not rejected) so this cosmetic display field
// can never block enrollment — see the deviceLabel handling in handleRegister.
const MAX_DEVICE_LABEL_CHARS = 64;

// Defensive cap on the inbound CSR PEM. PEM is ASCII so character count
// equals byte count, but `String.length` is UTF-16 code units — name the
// constant accordingly so future tightening (e.g. switching to TextEncoder)
// doesn't quietly change semantics. A P-256 PKCS#10 with the 5-RDN subject
// from PhotoAttest.generateCSR is ~830 bytes; 2K gives a ~2.5× safety margin
// for whitespace / future RDN additions while rejecting trivially malicious
// large bodies before pkijs touches them.
const MAX_CSR_PEM_CHARS = 2 * 1024;

/**
 * Request handler — pure function of (Request, deps) → Promise<Response>.
 * Imported by index_test.ts; production path wraps this in serve() below.
 */
export async function handleRegister(
  req: Request,
  deps: RegisterDeps = defaultDeps,
): Promise<Response> {
  const preflight = handlePreflight(req);
  if (preflight) return preflight;

  if (req.method !== "POST") {
    return jsonResponse({ error: "Method not allowed" }, { status: 405 });
  }

  const intermediatePem = deps.getIntermediatePem();
  if (!intermediatePem) {
    console.error("[register-signing-key] REALREEL_INTERMEDIATE_CERT_PEM unset");
    return jsonResponse({ error: "Server misconfiguration" }, { status: 500 });
  }

  const user = await deps.getUserFromAuthHeader(req);
  if (!user) {
    return jsonResponse({ error: "Unauthorized" }, { status: 401 });
  }

  // Conditional AAL2 gate: enrollment binds future signing authority to a
  // device, so it's treated like other sensitive actions in this codebase.
  // Users without MFA enrolled pass through unchanged. Users with MFA must
  // be at AAL2 (i.e. completed factor verification this session) — defends
  // against a phished/stolen AAL1 session being used to enroll an attacker
  // device on the victim's account.
  const aalReject = await deps.requireAal2IfMfaEnrolled(user);
  if (aalReject) return aalReject;

  // Per-user rate limit: prevents a buggy retry loop or a stolen-JWT spammer
  // from accumulating thousands of orphan rows in user_signing_keys.
  const rl = await deps.enforceRateLimit(
    "register-signing-key",
    user.id,
    RATE_LIMIT_WINDOWS,
  );
  if (!rl.ok) {
    return jsonResponse(
      { error: "Rate limit exceeded" },
      {
        status: 429,
        extraHeaders: { "Retry-After": String(rl.retryAfter) },
      },
    );
  }

  let body: RegisterBody;
  try {
    body = await req.json();
  } catch {
    return jsonResponse({ error: "Invalid JSON body" }, { status: 400 });
  }

  const {
    publicKey,
    platform,
    attestation,
    keyId,
    keyVersion,
    challenge,
    csr: csrPem,
    deviceLabel,
    supersedeKeyId,
  } = body;

  if (
    typeof publicKey !== "string" ||
    typeof platform !== "string" ||
    !ALLOWED_PLATFORMS.includes(platform as Platform) ||
    typeof attestation !== "string" ||
    typeof keyId !== "string" ||
    typeof keyVersion !== "string" ||
    typeof challenge !== "string" ||
    typeof csrPem !== "string"
  ) {
    return jsonResponse({ error: "Missing or malformed fields" }, { status: 400 });
  }

  // deviceLabel is a COSMETIC display field (Devices-screen row label, never
  // PII, persisted NULL when absent). It must never block enrollment — a user
  // unable to capture authentic photos because a display string is too long is
  // a disproportionate failure. So an over-long label is TRUNCATED to the cap
  // rather than rejected. (Seen in the wild: expo-device's Android `osName`
  // returns Build.VERSION.BASE_OS, which Samsung populates with a long
  // fingerprint string that overflowed the cap; Pixel leaves it empty, so its
  // "Android <ver>" label fit and only Samsung tripped the old 400.) A
  // non-string value is still a client bug → 400.
  let deviceLabelToPersist: string | null = null;
  if (deviceLabel !== undefined && deviceLabel !== null) {
    if (typeof deviceLabel !== "string") {
      return jsonResponse({ error: "Malformed deviceLabel" }, { status: 400 });
    }
    // Slicing by UTF-16 code unit can split a surrogate pair at the boundary,
    // leaving a dangling high surrogate. Drop it so we never persist an
    // unpaired surrogate — that's invalid UTF-8 and Postgres would reject the
    // text (turning this cosmetic field back into a hard failure, now a 500).
    // Slice first so the surrogate scan is bounded by the cap even for a
    // hostile oversized body. In practice the label is ASCII and the slice is
    // a no-op; the surrogate trim is defense-in-depth. Whitespace is NOT
    // normalized — the label is stored verbatim.
    const clamped = deviceLabel.slice(0, MAX_DEVICE_LABEL_CHARS);
    const lastUnit = clamped.charCodeAt(clamped.length - 1);
    deviceLabelToPersist =
      lastUnit >= 0xd800 && lastUnit <= 0xdbff ? clamped.slice(0, -1) : clamped;
  }

  // Accept both omitted (undefined) and explicit null. Today's client sends
  // undefined for initial enrollment; permitting null too costs nothing and
  // matches what a "no prior key" caller might naturally send.
  if (supersedeKeyId !== undefined && supersedeKeyId !== null) {
    if (
      typeof supersedeKeyId !== "string" ||
      supersedeKeyId.length === 0 ||
      supersedeKeyId.length > MAX_SIGNING_KEY_ID_CHARS
    ) {
      return jsonResponse({ error: "Malformed supersedeKeyId" }, { status: 400 });
    }
  }

  if (csrPem.length > MAX_CSR_PEM_CHARS) {
    return jsonResponse({ error: "CSR too large" }, { status: 413 });
  }
  // Outer-gate check is stricter than the parser: csrPemToDer also accepts
  // `-----BEGIN NEW CERTIFICATE REQUEST-----` (an older OpenSSL variant), but
  // native generateCSR on both iOS and Android only ever emits the canonical
  // `BEGIN CERTIFICATE REQUEST` form. The stricter check fails fast on
  // anything that doesn't look like our own client's output.
  if (!csrPem.includes("-----BEGIN CERTIFICATE REQUEST-----")) {
    return jsonResponse({ error: "Malformed csr" }, { status: 400 });
  }

  // === Burn the enrollment challenge atomically ===
  // Single-use by construction: consume_enrollment_challenge UPDATEs WHERE
  // consumed_at IS NULL AND expires_at > now(), so concurrent redeemers race
  // for the row and exactly one wins. Run BEFORE attestation parsing — the
  // cheap-fail path catches replays without spending CBOR/ASN.1 cycles.
  const supabase = deps.makeServiceRoleClient();
  const { data: burnedKeyVersion, error: burnErr } = await supabase.rpc(
    "consume_enrollment_challenge",
    { p_challenge: challenge, p_user_id: user.id },
  );
  if (burnErr) {
    // The RPC raises P0001 with message starting
    // "enrollment_challenge_unavailable" for unknown / expired / replayed
    // challenges. Surface as 400 — the client's recovery is to fetch a
    // fresh challenge. Any other error is a server bug.
    const code = (burnErr as { code?: string })?.code;
    const msg = (burnErr as { message?: string })?.message ?? "";
    if (code === "P0001" && msg.includes("enrollment_challenge_unavailable")) {
      return jsonResponse(
        { error: "Challenge expired or already used" },
        { status: 400 },
      );
    }
    console.error("[register-signing-key] burn RPC failed:", burnErr);
    return jsonResponse({ error: "Server error" }, { status: 500 });
  }
  // Defense in depth: ensure the client's claimed key_version matches what
  // the server recorded at issue time. Prevents a hostile client from
  // burning a challenge issued for v4 and registering under a different
  // version. burnedKeyVersion is the RPC's scalar text return.
  if (burnedKeyVersion !== keyVersion) {
    return jsonResponse({ error: "Challenge / keyVersion mismatch" }, { status: 400 });
  }

  // === Validate attestation ===
  // Decode all base64 inputs inside the try block so a malformed value from a
  // (JWT-authenticated) caller produces a clean 400 rather than an unhandled
  // atob InvalidCharacterError reaching the runtime.
  let challengeBytes: Uint8Array;
  let sePublicKey: Uint8Array;
  let attestationBytes: Uint8Array | null = null;
  try {
    challengeBytes = base64ToBytes(challenge);
    sePublicKey = base64ToBytes(publicKey);
    if (platform === "ios") attestationBytes = base64ToBytes(attestation);
  } catch (e) {
    console.warn(
      `[register-signing-key] base64 decode failed user=${user.id}: ${e instanceof Error ? e.message : String(e)}`,
    );
    return jsonResponse({ error: "Invalid attestation" }, { status: 400 });
  }

  // Parse + verify the CSR. Two checks the client cannot lie about:
  //   1. CSR self-signature verifies — proves possession of the private key
  //      corresponding to the SPKI inside the CSR.
  //   2. CSR's SPKI byte-equals the attested SE/StrongBox pubkey — binds the
  //      issuance to the hardware-attested key. Without this, an attacker
  //      could POST attested-pubkey-A alongside CSR-carrying-pubkey-B; the
  //      mismatch would only surface later at verifier-time.
  let csr;
  try {
    csr = deps.parseCSRFromPem(csrPem);
  } catch (e) {
    console.warn(
      `[register-signing-key] CSR parse failed user=${user.id}: ${
        e instanceof Error ? e.message : String(e)
      }`,
    );
    return jsonResponse({ error: "Malformed csr" }, { status: 400 });
  }
  try {
    await deps.verifyCSRSignature(csr);
  } catch (e) {
    console.warn(
      `[register-signing-key] CSR signature invalid user=${user.id}: ${
        e instanceof Error ? e.message : String(e)
      }`,
    );
    return jsonResponse({ error: "Invalid csr signature" }, { status: 400 });
  }
  const csrSpki = deps.extractCSRSpkiDer(csr);
  if (!ctEqual(csrSpki, sePublicKey)) {
    console.warn(
      `[register-signing-key] CSR SPKI does not match attested pubkey user=${user.id}`,
    );
    return jsonResponse(
      { error: "CSR public key does not match attested key" },
      { status: 400 },
    );
  }

  // Platform group + granted assurance level for leaf issuance (v2 semantics;
  // v1 ignores both). iOS is AL1 by policy (CP Apple-side CA validation
  // guidance is still "under development"). Android starts at AL1 and is
  // promoted to AL2 below iff the full CP Appendix A.3.1 evidence table
  // passes (validateAndroidAttestation's al2 evaluation); AL2-only failures
  // degrade, never reject. Promotion happens before issuance, so both
  // consumers — leafValidityDays and resolveV2LeafOptions — see the same
  // granted level (they must agree, or the leaf's c2pa-al OID and its
  // notAfter disagree).
  const leafPlatform: LeafPlatform = platform === "ios" ? "ios" : "android";
  let grantedAssurance: AssuranceLevel = "AL1";

  let appAttestPublicKey: Uint8Array | null = null;
  try {
    if (platform === "ios") {
      const { credCertPublicKey } = await deps.validateAppleAttestation({
        attestation: attestationBytes!, // decoded above; non-null on iOS branch
        challenge: challengeBytes,
        keyId,
        sePublicKey,
        appId: APPLE_APP_ID,
        requireProduction: REQUIRE_PRODUCTION_APPATTEST,
      });
      // Persist the credCert pubkey so the verifier can check upload-time App
      // Attest assertions without re-parsing the attestation blob.
      appAttestPublicKey = credCertPublicKey;
    } else {
      // android-strongbox or android-tee
      let certChainBase64: string[];
      try {
        certChainBase64 = JSON.parse(attestation);
      } catch {
        return jsonResponse({ error: "Invalid attestation" }, { status: 400 });
      }
      if (!Array.isArray(certChainBase64)) {
        return jsonResponse({ error: "Invalid attestation" }, { status: 400 });
      }
      // Patch-gate: reject enrollments whose leaf-cert osPatchLevel is older
      // than the rolling lookback window. Computing the threshold here (not in
      // the validator) keeps the validator a pure function of its inputs.
      const minOsPatchLevel = computeMinOsPatchLevel(
        new Date(),
        ANDROID_MIN_PATCH_LOOKBACK_MONTHS,
      );
      const androidResult = await deps.validateAndroidAttestation({
        certChainBase64,
        challenge: challengeBytes,
        sePublicKey,
        packageName: ANDROID_PACKAGE_NAME,
        expectedSecurityLevel:
          platform === "android-strongbox" ? "strongbox" : "tee",
        minOsPatchLevel,
        // Always evaluate the AL2 evidence table (even under v1) so fleet
        // AL2-eligibility is observable in logs before the v2 flip; the
        // granted level only shapes issuance under v2.
        al2: {
          signingCertSha256Digests: androidSigningCertDigestsFromEnv(),
          minAppVersionCode: androidMinAppVersionCodeFromEnv(),
          now: new Date(),
        },
      });
      if (androidResult.al2?.eligible) {
        grantedAssurance = "AL2";
      } else {
        console.log(
          `[register-signing-key] AL2 degraded to AL1 user=${user.id} ` +
            `failures=${androidResult.al2?.failures.join(",") ?? "not-evaluated"}`,
        );
      }
    }
  } catch (e) {
    if (e instanceof AttestationError) {
      console.warn(
        `[register-signing-key] attestation rejected user=${user.id} platform=${platform} code=${e.code} message=${e.message}`,
      );
      // Surface the patch-gate as a distinct error code so the client can
      // render an actionable "update your device" message. All other
      // AttestationError codes stay generic — leaking which check failed gives
      // an attacker a playbook for tweaking inputs until they get through.
      if (e.code === "ATTESTATION_STALE_PATCH") {
        return jsonResponse(
          { error: "Device security patch level out of date", code: e.code },
          { status: 400 },
        );
      }
    } else {
      console.error("[register-signing-key] unexpected validation error:", e);
    }
    return jsonResponse({ error: "Invalid attestation" }, { status: 400 });
  }

  // === Issue the CA-signed leaf via Cloud KMS ===
  // Private key never leaves KMS; we hand KMS a SHA-256(TBS) and get back a
  // DER ECDSA signature, then assemble the leaf locally. Any failure here
  // is a 500 (server-side), not a 400 — the client did nothing wrong.
  //
  // Before issuance, confirm REALREEL_INTERMEDIATE_CERT_PEM corresponds to
  // the KMS resource at GCP_KMS_KEY_RESOURCE (cached once per cold start).
  // Catches rotation-induced config drift before it produces a window of
  // bad certs.
  let leafChainPEM: string;
  let certSerialDecimal: string;
  let leafExpiresAt: Date;
  // Resolved inside the try: a junk CA_HIERARCHY throws CA_CONFIG_INVALID,
  // which belongs in the structured 500 below rather than escaping the
  // handler as an unshaped serve()-level error.
  let hierarchy: CaHierarchy = "v1";
  try {
    hierarchy = caHierarchy();
    const kmsCreds = await deps.loadKmsCredentials();
    await deps.ensureIntermediateMatchesKms(kmsCreds, intermediatePem);
    const issued = await deps.issueLeafChainFromCSR(csr, {
      intermediatePem,
      validityDays: leafValidityDays(hierarchy, leafPlatform, grantedAssurance),
      signer: (digest) =>
        deps.kmsSignDigest(
          digest,
          kmsCreds,
          hierarchy === "v2" ? "sha384" : "sha256",
        ),
      // Resolves the per-platform CPL record UUID + AIA URLs from env; throws
      // CA_CONFIG_INVALID (→ 500 here) if v2 is active without a configured
      // UUID, so a half-configured flip can't mint a leaf missing its CPL
      // binding.
      v2: hierarchy === "v2"
        ? resolveV2LeafOptions(leafPlatform, grantedAssurance)
        : undefined,
    });
    leafChainPEM = issued.pem;
    // Persist alongside the cert PEM so the verifier can look up the
    // revocation row by the same serial c2pa-node exposes via
    // signature_info.cert_serial_number.
    certSerialDecimal = issued.serialDecimal;
    // Mirror the issued leaf's notAfter onto the row so the Devices screen can
    // render "Expires in X days" without parsing the PEM. The verifier still
    // trusts the cert chain's own notAfter; this column is a UI projection.
    leafExpiresAt = issued.notAfter;
  } catch (e) {
    if (e instanceof AttestationError) {
      console.error(
        `[register-signing-key] leaf issuance failed user=${user.id} code=${e.code}: ${e.message}`,
      );
    } else {
      console.error("[register-signing-key] leaf issuance failed:", e);
    }
    return jsonResponse({ error: "Issuance failed" }, { status: 500 });
  }

  // === Persist via RPC (just INSERT; multi-device design) ===
  // (supabase service-role client was built above for the burn RPC; reuse it.)

  // For Postgres bytea params via PostgREST, we encode bytes as base64-prefixed
  // hex literals — but supabase-js will accept Uint8Array transparently in the
  // RPC call as long as the function signature is bytea. Easiest: pass bytes
  // as `\x<hex>` literals which Postgres accepts on input.
  const publicKeyHex = "\\x" + bytesToHex(sePublicKey);
  const attestationBlobBytes = platform === "ios"
    ? attestationBytes! // already decoded above; reuse instead of decoding twice
    : new TextEncoder().encode(attestation); // store the JSON as bytes for Android
  const attestationBlobHex = "\\x" + bytesToHex(attestationBlobBytes);

  // Derive a uniform key_id from the SE signing public key. iOS's body.keyId
  // is Apple's App Attest keyId (a different key, used for cert-chain
  // attestation only) and we already validated it; Android's body.keyId is
  // the keystore alias which is constant per app and would PK-collide on
  // re-enrollment. SHA-256(publicKey) gives us a globally-unique, cross-
  // platform identifier that's stable for the lifetime of one keypair.
  const dbKeyIdBytes = new Uint8Array(
    await crypto.subtle.digest("SHA-256", sePublicKey as BufferSource),
  );
  const dbKeyId = bytesToBase64(dbKeyIdBytes);

  const { error } = await supabase.rpc("register_user_signing_key", {
    p_user_id: user.id,
    p_key_version: keyVersion,
    p_public_key: publicKeyHex,
    p_platform: platform,
    p_attestation_blob: attestationBlobHex,
    p_key_id: dbKeyId,
    p_leaf_cert_pem: leafChainPEM,
    p_cert_serial_number: certSerialDecimal,
    p_expires_at: leafExpiresAt.toISOString(),
    p_device_label: deviceLabelToPersist,
    // iOS only — Android rows stay NULL by design (no App Attest equivalent).
    p_app_attest_public_key: appAttestPublicKey
      ? "\\x" + bytesToHex(appAttestPublicKey)
      : null,
    // When the client is re-enrolling and wants the prior row marked
    // "superseded" (hidden from the Devices list while still verifier-
    // valid for pending uploads), it passes the prior canonical key_id.
    // Initial enrollment omits this → no supersede.
    p_supersede_key_id: supersedeKeyId ?? null,
  });

  if (error) {
    // 23505 = unique_violation — likely a key_id replay (someone re-submitting
    // an attestation that was already used). Surface as 409 so the client can
    // distinguish from validation failures.
    if ((error as { code?: string })?.code === "23505") {
      return jsonResponse({ error: "Key already registered" }, { status: 409 });
    }
    // Spread the PostgrestError fields explicitly. Console.error on an object
    // can print as "[object Object]" depending on the runtime — losing the
    // Postgres `code`, `message`, `details`, `hint` that diagnoses the
    // actual failure (FK violation, CHECK violation, NOT NULL, type
    // mismatch). The keys come straight off PostgrestError (supabase-js v2).
    //
    // PostgrestError.details on NOT NULL / CHECK violations can echo offending
    // row column values. Safe here because every user_signing_keys column is
    // non-confidential by design (public_key / leaf_cert_pem /
    // attestation_blob / cert_serial_number are all surfaced server-side or in
    // the C2PA manifest). Re-evaluate if a future column adds something secret.
    const pgErr = error as {
      code?: string;
      message?: string;
      details?: string;
      hint?: string;
    };
    console.error(
      "[register-signing-key] RPC failed:",
      `code=${pgErr.code ?? "?"}`,
      `message=${pgErr.message ?? "?"}`,
      `details=${pgErr.details ?? "?"}`,
      `hint=${pgErr.hint ?? "?"}`,
      `user_id=${user.id}`,
      `platform=${platform}`,
    );
    return jsonResponse({ error: "Persist failed" }, { status: 500 });
  }

  console.log(
    `[register-signing-key] enrolled user=${user.id} platform=${platform} key_version=${keyVersion}` +
      (hierarchy === "v2" ? ` assurance=${grantedAssurance}` : ""),
  );
  // v2 surfaces the granted assurance level so the client can show which
  // level this device actually enrolled at (AL2 evidence failures degrade to
  // AL1 rather than rejecting; the user should be able to see that).
  return jsonResponse({
    ok: true,
    leafChainPEM,
    keyId: dbKeyId,
    ...(hierarchy === "v2" ? { assuranceLevel: grantedAssurance } : {}),
  });
}

function bytesToHex(bytes: Uint8Array): string {
  let s = "";
  for (let i = 0; i < bytes.length; i++) {
    s += bytes[i].toString(16).padStart(2, "0");
  }
  return s;
}

// ANDROID_APP_SIGNING_CERT_SHA256: comma-separated hex SHA-256 digests of the
// registered APK signing certificate(s) — Play App Signing cert in prod, the
// debug keystore cert on a local stack. Malformed entries are dropped with a
// warning; an empty result just means the AL2 signing-cert row can't pass
// (degrade to AL1), never a rejection.
export function androidSigningCertDigestsFromEnv(): Uint8Array[] {
  const raw = Deno.env.get("ANDROID_APP_SIGNING_CERT_SHA256") ?? "";
  const out: Uint8Array[] = [];
  for (const entry of raw.split(",").map((s) => s.trim()).filter(Boolean)) {
    if (!/^[0-9a-fA-F]{64}$/.test(entry)) {
      console.warn(
        "[register-signing-key] ANDROID_APP_SIGNING_CERT_SHA256 entry is not 64 hex chars; ignoring",
      );
      continue;
    }
    const bytes = new Uint8Array(32);
    for (let i = 0; i < 32; i++) {
      bytes[i] = parseInt(entry.slice(i * 2, i * 2 + 2), 16);
    }
    out.push(bytes);
  }
  return out;
}

// ANDROID_MIN_APP_VERSION_CODE: optional versionCode floor for the AL2
// attestationApplicationID row. Doubles as the Gen Agmt §4.2 mandated-change
// lever (raise it to retire non-conformant builds as their leaves expire).
export function androidMinAppVersionCodeFromEnv(): number | undefined {
  const raw = Deno.env.get("ANDROID_MIN_APP_VERSION_CODE");
  if (!raw) return undefined;
  const n = Number(raw);
  if (!Number.isInteger(n) || n < 0) {
    console.warn(
      "[register-signing-key] ANDROID_MIN_APP_VERSION_CODE is not a non-negative integer; ignoring",
    );
    return undefined;
  }
  return n;
}

/**
 * Compute the minimum-acceptable Keymaster osPatchLevel in YYYYMM form, given
 * the current date and a lookback window in months.
 *
 * `Date.setUTCMonth(m)` accepts out-of-range month indices (e.g. -3 rolls the
 * year back), which gives the "12 months ago" lookback without wrap logic.
 *
 * Boundary semantics: the validator uses strict `<` (not `<=`), so a device
 * patched exactly `lookbackMonths` ago (osPatchLevel == the value this
 * returns) is ACCEPTED — flipping to `<=` here without flipping the comparison
 * would shift the gate by one month.
 */
export function computeMinOsPatchLevel(
  now: Date,
  lookbackMonths: number,
): number {
  const cutoff = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), 1));
  cutoff.setUTCMonth(cutoff.getUTCMonth() - lookbackMonths);
  return cutoff.getUTCFullYear() * 100 + (cutoff.getUTCMonth() + 1);
}

// Only start the HTTP server when this module is run directly; tests import
// handleRegister and would otherwise trip Deno.listen() at module load.
if (import.meta.main) {
  serve((req: Request) => handleRegister(req));
}
