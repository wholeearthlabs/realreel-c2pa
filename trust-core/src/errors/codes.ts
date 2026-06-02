// C2PA verify-error taxonomy. Single source of truth shared between the
// Cloud Run verifier (returns these in 422 response bodies, tags them in
// Sentry) and the React Native client (maps the subset it handles to
// user-facing toasts via lib/captureErrors.ts).
//
// Stability contract: codes are stable strings. They appear in:
//   - Server response bodies (verify-and-create-media reject path).
//   - Sentry tags (`verify_error.<CODE>` captureMessage names + `code` tag).
//   - Client toast routing tables.
//   - pgTAP test assertions on the SQL layer below the verifier.
// Adding a new code is fine — both client and server have fallback paths
// for unknown codes. Renaming an existing code is a breaking change that
// requires coordinated client/server/SQL deploys.

export const VerifyErrorCode = {
  /** Manifest's Stage 1 or Stage 2 signing key is revoked (revoked_at IS NOT NULL). */
  KEY_REVOKED: "KEY_REVOKED",

  /** Manifest's signing key is not in user_signing_keys at all. Treated as
   * equivalent-to-revoked from the user's perspective — same recovery
   * (re-enroll) and same toast bucket. Distinct code for telemetry. */
  KEY_NOT_FOUND: "KEY_NOT_FOUND",

  /** Leaf cert past its notAfter (or notBefore in the future). c2pa-node's
   * chain validation surfaces this as a validation_status code; we
   * normalize. */
  CERT_EXPIRED: "CERT_EXPIRED",

  /** Manifest's cryptographic signature failed to verify, OR an assertion
   * hash didn't match its referent in the asset, OR similar tamper signal
   * from c2pa-node. */
  SIGNATURE_INVALID: "SIGNATURE_INVALID",

  /** Manifest is structurally invalid: missing required assertions for the
   * profile, malformed JUMBF, missing parent ingredient for a RealReel
   * Stage-2 manifest, etc. */
  MANIFEST_MALFORMED: "MANIFEST_MALFORMED",

  /** Cert chain doesn't root to any trust anchor in trust-sources.yaml.
   * c2pa-node returns signingCredential.untrusted; we map. */
  UNTRUSTED_ISSUER: "UNTRUSTED_ISSUER",

  /** Verifier hit an internal error (Postgres unreachable, c2pa-node
   * panic, etc.) that isn't attributable to the input. Client should
   * retry. */
  VERIFIER_UNAVAILABLE: "VERIFIER_UNAVAILABLE",

  /** Storage fetch failed or returned unexpected content — signed URL
   * 4xx/5xx, content-length mismatch, If-Match (TOCTOU) failure, host
   * regex rejection. Emitted by both the verifier (HEAD failed) and the
   * verify-and-create-media edge function (sign URL failed). */
  STORAGE_FETCH_FAILED: "STORAGE_FETCH_FAILED",

  /** Bearer auth on /verify failed. Edge function sends Authorization;
   * verifier rejects with 401 if it doesn't match VERIFIER_SHARED_SECRET. */
  UNAUTHORIZED: "UNAUTHORIZED",

  /** Storage path doesn't match the caller's RLS prefix. Emitted only by
   * the verify-and-create-media edge function (never the verifier
   * microservice). Indicates a caller tried to verify a file owned by a
   * different user — defense-in-depth against a JWT/storage mismatch. */
  STORAGE_PATH_FORBIDDEN: "STORAGE_PATH_FORBIDDEN",

  /** Post-verification INSERT into `media` failed. Emitted only by the
   * verify-and-create-media edge function after the verifier said OK.
   * Typical causes: RLS regression, unique-violation, schema drift. */
  INSERT_FAILED: "INSERT_FAILED",

  /** Manifest lacks the expected `org.realreel.app_attest` (iOS) or
   * `org.realreel.play_integrity` (Android) envelope, OR the envelope
   * fields are missing/malformed. Closes the rooted-device arbitrary-
   * signing gap: every signed manifest must carry a fresh platform
   * attestation. */
  ATTESTATION_MISSING: "ATTESTATION_MISSING",

  /** The platform attestation blob failed validation — bad signature,
   * mismatched clientDataHash, or chain doesn't terminate at Apple /
   * Google's attestation root. */
  ATTESTATION_INVALID: "ATTESTATION_INVALID",

  /** A token-reuse signal — the server-issued Stage-2 challenge was
   *  already consumed. Burned by `consume_and_record_attestation` in a
   *  single atomic UPDATE; concurrent redeemers race for the row, exactly
   *  one wins, the rest raise this code. Single-use nonce burn is the
   *  sole anti-replay primitive. */
  ATTESTATION_REPLAY: "ATTESTATION_REPLAY",
} as const;

export type VerifyErrorCode = typeof VerifyErrorCode[keyof typeof VerifyErrorCode];
