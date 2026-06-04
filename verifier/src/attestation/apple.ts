// App Attest assertion validator (iOS) — Stage-2 upload attestation.
//
// Enforces the Stage-2 app-integrity gate described in
// TRUST_ARCHITECTURE.md, closing the scaled-distribution attack
// (forked APK / mass replay of a tampered build).
//
// Enforced for the Stage-2 upload manifest:
//
//   1. Structural presence — the manifest carries the
//      `org.realreel.app_attest` assertion with well-formed { keyId,
//      challenge, assertion, platform: "ios" } fields.
//   2. Apple cryptographic chain validation — CBOR-decode the assertion,
//      verify Apple's ECDSA signature over
//      `authenticatorData || SHA256(challenge || SE_SPKI)` against the
//      App Attest credCert pubkey persisted at enrollment, and check
//      rpIdHash matches SHA256("<TeamID>.<BundleID>"). MANDATORY — a row
//      missing the stored pubkey is rejected upstream (no nonce-only
//      fallback). This rejects repackaged / non-Apple-signed builds: App
//      Attest verifies the on-disk app package against genuine Apple
//      hardware, so a forked or re-signed binary can't produce a valid
//      assertion. It does NOT detect runtime hooking or jailbreak — a
//      genuine code-signed binary, hooked at runtime, can still emit a valid
//      assertion. That runtime-tampering residual is accepted (see
//      TRUST_ARCHITECTURE.md "Scope and assumptions").
//   3. Single-use challenge consumption — atomic UPDATE burns the server-
//      issued nonce (the sole anti-replay; counter-monotonicity is not
//      enforced).

import { Buffer } from "node:buffer";

import { decode as cborDecode } from "cbor-x";

import { postgresAdapter } from "../db.js";
import type { NonceBurner } from "../ports.js";
import { VerifyError, VerifyErrorCode } from "../errors.js";
import type { AssertionShape, ManifestShape } from "../c2pa-shape.js";
import {
  concat,
  ctEqual,
  importP256RawPubkey,
  sha256,
  verifyEcdsaP256Sha256,
} from "./pki-node.js";

// Single source of truth lives in @realreel/c2pa-trust-core; re-exported
// here so existing call sites importing it from this module keep working.
import { APP_ATTEST_LABEL } from "@realreel/c2pa-trust-core";
export { APP_ATTEST_LABEL };

/**
 * ===== PER-APP SWAP-POINT: Apple App Attest identity (iOS) =====
 *
 * "<TeamID>.<BundleID>" — Apple's appId. rpIdHash inside authenticatorData
 * is `SHA256(APPLE_APP_ID)`. A fork MUST set these to its own Apple Developer
 * Team ID + iOS bundle identifier; the defaults below are RealReel's.
 *
 * Sourced from env when present (`APPLE_TEAM_ID`, `APPLE_BUNDLE_ID`) so a
 * forker can override per-deployment without editing code; falls back to the
 * RealReel values so the test suite and the standard deploy run with no env
 * set. This MUST stay in lockstep with the CA-side copy in
 * `ca/_shared/config.ts` (the verifier is a separate Node project and can't
 * import the Deno code). There is no migration path for already-enrolled keys
 * whose attestation bound the old appId — changing these invalidates every
 * existing iOS enrollment.
 */
export const APPLE_TEAM_ID = process.env.APPLE_TEAM_ID ?? "7RPHYY66U6";
export const APPLE_BUNDLE_ID = process.env.APPLE_BUNDLE_ID ?? "com.realreel.app";
export const APPLE_APP_ID = `${APPLE_TEAM_ID}.${APPLE_BUNDLE_ID}`;

// All VerifyErrors thrown from this file carry `category: 'app-attest'`
// so server-side Sentry alerts can filter on iOS-specific failures
// independently from Android. See verifier/OPERATIONS.md § "Monitoring +
// alerts" for the alert spec.
function aaVerifyError(code: VerifyErrorCode, detail: string): VerifyError {
  return new VerifyError(code, detail, { category: "app-attest" });
}

/** Shape of the org.realreel.app_attest assertion data emitted by
 * native/ios/PhotoAttestModule.swift. Mirrored here so
 * the verifier doesn't have to import from the mobile-app types. */
export interface AppAttestAssertionData {
  keyId: string;
  challenge: string;
  assertion: string;
  platform: string;
}

/**
 * Find and structurally validate the app_attest assertion on a single
 * manifest stage. Throws VerifyError if missing or malformed. Returns
 * the parsed envelope otherwise.
 */
function extractAppAttestData(
  manifest: ManifestShape,
  stageLabel: string,
): AppAttestAssertionData {
  const found = (manifest.assertions ?? []).find(
    (a: AssertionShape) => a.label === APP_ATTEST_LABEL,
  );
  if (!found) {
    throw aaVerifyError(
      VerifyErrorCode.ATTESTATION_MISSING,
      `${stageLabel} manifest lacks ${APP_ATTEST_LABEL} assertion`,
    );
  }
  const data = found.data as Partial<AppAttestAssertionData> | undefined;
  if (
    !data ||
    typeof data.keyId !== "string" ||
    typeof data.challenge !== "string" ||
    typeof data.assertion !== "string" ||
    typeof data.platform !== "string"
  ) {
    throw aaVerifyError(
      VerifyErrorCode.ATTESTATION_INVALID,
      `${stageLabel} ${APP_ATTEST_LABEL} is malformed`,
    );
  }
  if (data.platform !== "ios") {
    throw aaVerifyError(
      VerifyErrorCode.ATTESTATION_INVALID,
      `${stageLabel} ${APP_ATTEST_LABEL} platform must be 'ios' (got '${data.platform}')`,
    );
  }
  if (!isBase64(data.keyId) || !isBase64(data.challenge) || !isBase64(data.assertion)) {
    throw aaVerifyError(
      VerifyErrorCode.ATTESTATION_INVALID,
      `${stageLabel} ${APP_ATTEST_LABEL} contains non-base64 fields`,
    );
  }
  return data as AppAttestAssertionData;
}

function isBase64(value: string): boolean {
  if (value.length === 0) return false;
  // Permissive RFC 4648 alphabet (both standard `+/` and URL-safe `-_`).
  // Final-pad rules vary across emitters (Swift's base64EncodedString
  // uses standard padding; some tooling drops it). Strict length-mod-4
  // validation here would produce false negatives. The crypto path
  // decodes with Buffer.from(..., 'base64url'), which accepts both
  // alphabets, so this alphabet is the source of truth for what we'll
  // successfully decode downstream.
  return /^[A-Za-z0-9+/=_-]+$/.test(value);
}

/**
 * Validate the App Attest assertion attached to a manifest stage. Pure
 * structural check — no DB side effects. Throws on missing or malformed
 * envelope; returns the parsed envelope otherwise.
 *
 * Splitting structural validation from challenge consumption lets the
 * realreel profile validate BOTH stages' structures before burning ANY
 * stage's nonce. Without the split, a malformed Stage-2 would still cost
 * Stage-1's single-use nonce — bad UX for transient failures.
 */
export function validateAppAttestStructure(
  manifest: ManifestShape,
  stageLabel: string,
): AppAttestAssertionData {
  return extractAppAttestData(manifest, stageLabel);
}

/**
 * Crypto inputs for App Attest assertion verification: the per-device App
 * Attest credCert public key + the SE signing key's SPKI. Both are persisted
 * on user_signing_keys and surfaced via lookup_signing_key_revocation. They
 * are MANDATORY — the realreel profile rejects a Stage-2 app_attest upload
 * whose registry row lacks either (no nonce-only fallback); a NOT NULL DB
 * constraint enforces the same invariant.
 */
export interface AppAttestCryptoInputs {
  /** X9.63 uncompressed P-256 public key (0x04 || X(32) || Y(32), 65
   * bytes) of the Apple App Attest credCert for this device. Persisted at
   * enrollment from validateAppleAttestation's credCertPublicKey output. */
  appAttestPublicKey: Uint8Array;
  /** DER SPKI of the device's signing key (SE / hardware-attested public
   * key). Used to reconstruct clientData = SHA256(challenge || SE_SPKI),
   * which iOS native code SHA-256-hashes and passes to
   * DCAppAttestService.generateAssertion as the clientDataHash. */
  signingKeySpki: Uint8Array;
}

/**
 * Decoded shape of Apple's App Attest assertion CBOR. Per Apple's
 * documentation ("Validating Apps That Connect to Your Server"), the
 * top-level object is a CBOR map with exactly two keys:
 *   - `signature`: DER ECDSA-P256 signature over `compositeData`.
 *   - `authenticatorData`: WebAuthn-style auth data (rpIdHash + flags +
 *     counter), used both to extract the counter and as the prefix of
 *     compositeData.
 */
interface DecodedAssertion {
  signature: Uint8Array;
  authenticatorData: Uint8Array;
}

/**
 * Apple cryptographic chain validation + atomic single-use nonce burn.
 *
 * Algorithm:
 *   1. CBOR-decode the base64 `envelope.assertion` → { signature,
 *      authenticatorData }.
 *   2. Validate authenticatorData layout: ≥37 bytes (rpIdHash 32 +
 *      flags 1 + counter 4). Reject otherwise.
 *   3. rpIdHash := SHA256("<TeamID>.<BundleID>"). Reject mismatch.
 *   4. clientDataHash := SHA256(challenge_bytes || SE_SPKI_bytes).
 *   5. compositeData := authenticatorData || clientDataHash.
 *   6. ECDSA-verify(SHA256(compositeData), signature, credCertPubKey).
 *      Reject mismatch.
 *   7. Extract counter (4-byte big-endian uint32 at offset 33) — folded
 *      into the signed authenticatorData, so it is signature-verified, but
 *      its value is NOT enforced (counter-monotonicity is not used).
 *   8. Call consume_and_record_attestation(key_id, nonce) — atomic
 *      single-use nonce burn (the sole anti-replay).
 *
 * The crypto inputs (stored credCert pubkey + SE SPKI) are mandatory: an
 * App Attest assertion is only meaningful verified against the enrollment-
 * stored pubkey. The caller (realreel profile) rejects up front when the
 * registry row lacks them, so there is no nonce-only fallback.
 *
 * The signing-cert key_id supplied by the caller binds the nonce to the
 * correct device: replays of a nonce minted for key A cannot be redeemed
 * against key B (attestation_challenges PK is `(key_id, nonce)`).
 */
export async function consumeAppAttestForStage(
  envelope: AppAttestAssertionData,
  signingKeyId: string,
  stageLabel: string,
  crypto: AppAttestCryptoInputs,
  nonceBurner: NonceBurner = postgresAdapter,
): Promise<void> {
  // Verify the assertion against the stored credCert pubkey (throws on a bad
  // signature). The signature-verified counter inside authenticatorData is
  // discarded — the single-use nonce burn below is the sole anti-replay
  // primitive.
  await verifyAppAttestAssertion(envelope, signingKeyId, stageLabel, crypto);

  try {
    await nonceBurner.burn(signingKeyId, envelope.challenge);
  } catch (e) {
    const msg = (e as Error).message ?? "";
    if (msg.includes("attestation_challenge_unavailable")) {
      throw aaVerifyError(
        VerifyErrorCode.ATTESTATION_REPLAY,
        `${stageLabel} ${msg}`,
      );
    }
    throw e;
  }
}

/**
 * Crypto-only App Attest validation (no DB writes / no nonce burn —
 * `consumeAppAttestForStage` layers the burn on top). Returns the assertion
 * counter (signature-verified but not enforced; the caller discards it).
 * `signingKeyId` is accepted for call-site symmetry but unused here (the
 * crypto is keyed entirely off `crypto`).
 */
export async function verifyAppAttestAssertion(
  envelope: AppAttestAssertionData,
  _signingKeyId: string,
  stageLabel: string,
  crypto: AppAttestCryptoInputs,
): Promise<bigint> {
  return await validateAssertionCrypto(envelope, stageLabel, crypto);
}

/**
 * Crypto chain validation: CBOR-decode + chain-verify + extract counter.
 * Returns the counter on success; throws ATTESTATION_INVALID with a stage-
 * prefixed detail on any cryptographic failure.
 *
 * Kept private + side-effect-free (no DB calls). The DB layer happens in
 * the caller after this returns the counter, so a crypto failure never
 * burns a nonce.
 */
async function validateAssertionCrypto(
  envelope: AppAttestAssertionData,
  stageLabel: string,
  crypto: AppAttestCryptoInputs,
): Promise<bigint> {
  // === 1. CBOR-decode the assertion ===
  // Buffer.from('base64url') accepts both standard and URL-safe alphabets,
  // matching the permissive isBase64() structural check. A wrong alphabet
  // produces shorter bytes that then fail the CBOR-decode / authData-length /
  // signature steps as ATTESTATION_INVALID — no separate base64 try/catch.
  const assertionBytes = Buffer.from(envelope.assertion, "base64url");

  let decoded: DecodedAssertion;
  try {
    const obj = cborDecode(assertionBytes) as unknown;
    decoded = assertObjectShape(obj, stageLabel);
  } catch (e) {
    if (e instanceof VerifyError) throw e;
    throw aaVerifyError(
      VerifyErrorCode.ATTESTATION_INVALID,
      `${stageLabel} CBOR decode failed: ${(e as Error).message}`,
    );
  }

  // === 2. Validate authenticatorData layout ===
  // The Stage-2 path needs only the rpIdHash (bytes 0..32) and counter
  // (bytes 33..37). The longer "attested credential data" section is
  // enrollment-only — assertions never carry it.
  const authData = decoded.authenticatorData;
  if (authData.length < 37) {
    throw aaVerifyError(
      VerifyErrorCode.ATTESTATION_INVALID,
      `${stageLabel} authenticatorData < 37 bytes (got ${authData.length})`,
    );
  }
  const rpIdHash = authData.subarray(0, 32);
  // counter is a big-endian uint32 starting at byte 33. Decoded for
  // signature-verification completeness (it's part of authenticatorData) but
  // the value is discarded — monotonicity is not enforced. The `>>> 0` MUST
  // be the outermost op so high-bit-set values decode as positive uint32
  // rather than negative Int32.
  const counter = BigInt(
    ((authData[33]! << 24) |
      (authData[34]! << 16) |
      (authData[35]! << 8) |
      authData[36]!) >>> 0,
  );

  // === 3. rpIdHash := SHA256(APPLE_APP_ID) ===
  const expectedRpIdHash = await sha256(new TextEncoder().encode(APPLE_APP_ID));
  if (!ctEqual(rpIdHash, expectedRpIdHash)) {
    throw aaVerifyError(
      VerifyErrorCode.ATTESTATION_INVALID,
      `${stageLabel} rpIdHash mismatch (assertion authData does not bind ${APPLE_APP_ID})`,
    );
  }

  // === 4. clientDataHash := SHA256(challenge || SE_SPKI) ===
  // The binding is the server nonce the iOS native module fed into
  // DCAppAttestService.generateAssertion's clientDataHash (base64-decoded from
  // envelope.challenge), concatenated with the SE pubkey's SPKI DER bytes
  // (== stored user_signing_keys.public_key). Folding SE_SPKI in defeats
  // assertion-stapling: an assertion is only valid for the exact signing key
  // it was minted against. The caller burns the nonce after this returns.
  const bindingBytes = Buffer.from(envelope.challenge, "base64url");
  const clientDataHash = await sha256(
    concat(bindingBytes, crypto.signingKeySpki),
  );

  // === 5. nonce = SHA256(authenticatorData || clientDataHash) ===
  //
  // Apple's App Attest assertion signing scheme is NOT the WebAuthn-style
  // `ECDSA-SHA256(authData || clientDataHash)`. Per Apple's "Assessing
  // Fraud Risk" docs, the assertion signature is computed over a *nonce*
  // which is itself `SHA256(authenticatorData || clientDataHash)`, then
  // signed with the credCert's private key using ECDSA-SHA256. Net effect
  // is double SHA-256:
  //
  //     nonce     = SHA256(authData || clientDataHash)
  //     signed    = ECDSA-SHA256(nonce, credCertPrivKey)
  //               = ECDSA-primitive(SHA256(nonce), credCertPrivKey)
  //               = ECDSA-primitive(SHA256(SHA256(authData || clientDataHash)),
  //                                  credCertPrivKey)
  //
  // The single-SHA256 / WebAuthn interpretation also produces a clean
  // structural / length / rpIdHash pass, then fails ECDSA — this exact
  // mismatch was found empirically by testing real iPhone assertions
  // through both schemes; only the double-hash variant verified.
  //
  // To verify with Node's `crypto.verify("sha256", msg, ...)` (which
  // SHA-256s its msg input then ECDSA-primitive-verifies), we pass
  // `nonce` as msg. The library hashes again internally → matches the
  // double-hash that Apple did at sign time.
  const compositeData = concat(authData, clientDataHash);
  const nonce = await sha256(compositeData);

  // === 6. ECDSA-verify ===
  let pubkey;
  try {
    pubkey = importP256RawPubkey(crypto.appAttestPublicKey);
  } catch (e) {
    // Bad pubkey shape stored at enrollment — surfaces as
    // ATTESTATION_INVALID. The enrollment flow should have rejected this
    // shape, so reaching here means an enrollment-time bug.
    throw aaVerifyError(
      VerifyErrorCode.ATTESTATION_INVALID,
      `${stageLabel} stored App Attest public key is not a valid P-256 uncompressed point: ${(e as Error).message}`,
    );
  }
  let sigOk = false;
  try {
    sigOk = verifyEcdsaP256Sha256(nonce, decoded.signature, pubkey);
  } catch (e) {
    // node:crypto.verify throws on malformed DER signatures.
    throw aaVerifyError(
      VerifyErrorCode.ATTESTATION_INVALID,
      `${stageLabel} ECDSA verify threw: ${(e as Error).message}`,
    );
  }
  if (!sigOk) {
    throw aaVerifyError(
      VerifyErrorCode.ATTESTATION_INVALID,
      `${stageLabel} App Attest assertion signature did not verify against credCert pubkey`,
    );
  }

  return counter;
}

/**
 * Narrow a cbor-x decoded value to the expected DecodedAssertion shape.
 * cbor-x returns plain objects for CBOR maps with string keys, and
 * Uint8Array (typed array) for CBOR byte strings. We only accept the
 * shape Apple documents — strict checks here keep a malformed CBOR
 * (with extra keys, wrong types, or a top-level array) from sliding
 * into the signature-verify step with a partially-populated object.
 */
function assertObjectShape(obj: unknown, stageLabel: string): DecodedAssertion {
  if (obj === null || typeof obj !== "object" || Array.isArray(obj)) {
    throw aaVerifyError(
      VerifyErrorCode.ATTESTATION_INVALID,
      `${stageLabel} CBOR root is not an object`,
    );
  }
  const map = obj as Record<string, unknown>;
  const signature = coerceBytes(map.signature);
  const authenticatorData = coerceBytes(map.authenticatorData);
  if (!signature) {
    throw aaVerifyError(
      VerifyErrorCode.ATTESTATION_INVALID,
      `${stageLabel} assertion CBOR missing 'signature' bytes`,
    );
  }
  if (!authenticatorData) {
    throw aaVerifyError(
      VerifyErrorCode.ATTESTATION_INVALID,
      `${stageLabel} assertion CBOR missing 'authenticatorData' bytes`,
    );
  }
  return { signature, authenticatorData };
}

function coerceBytes(v: unknown): Uint8Array | null {
  // cbor-x always emits CBOR byte strings as Uint8Array (or Node Buffer,
  // a Uint8Array subclass). No ArrayBuffer fallback needed.
  return v instanceof Uint8Array ? v : null;
}

// Re-export for tests + future callers.
export { extractAppAttestData };

/**
 * True iff the manifest carries an org.realreel.app_attest assertion.
 * Used by the realreel profile's envelope dispatch — in lenient dev mode
 * the envelope is validated when present and tolerated when absent; in
 * required mode an absent envelope is a hard reject.
 */
export function hasAppAttestAssertion(manifest: ManifestShape): boolean {
  return (manifest.assertions ?? []).some(
    (a: AssertionShape) => a.label === APP_ATTEST_LABEL,
  );
}
