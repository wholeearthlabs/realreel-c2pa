// RealReel verification profile — the single ingestion profile (force-wrap).
//
// Every accepted upload's ACTIVE (Stage 2) manifest is RealReel-signed;
// verify.ts enforces that before dispatching here, so a raw single-stage
// foreign-issuer file (e.g. a Pixel capture uploaded directly) is rejected
// at ingestion. This profile handles the two Stage-1 shapes:
//
//   1. Native RealReel: Stage 1 (capture, parent) and Stage 2 (upload,
//      active) both signed by the uploader's RealReel-enrolled hardware key.
//   2. Cross-issuer wrap: Stage 1 signed by a non-RealReel trusted camera
//      (Pixel today; future Sony / Leica / Nikon), Stage 2 signed by the
//      uploader's RealReel key.
//
// By the time this runs, c2pa-node has parsed the manifest store, validated
// each signature, walked each cert chain to a trust anchor in
// trust-sources.yaml, and reported any tamper / validation issues in
// validation_status[].
//
// Trust in the capture is enrollment-only: it rests on the Stage-1 cert
// chaining to a trusted root (the RealReel CA, or a trusted vendor like
// Pixel) plus the structural fresh-capture + action allowlist — the same
// model Pixel's C2PA camera and iOS App Attest use. There is NO per-capture
// device-health check; Stage-1 device-health envelopes are not processed.
//
// The verifier is user-anonymous: Stage-1 user_id is UNBOUND in both modes
// (native enables the cross-user "Bob captures, Sara uploads" flow; wrap
// mode has no RealReel key for the parent by construction), and the Stage-2
// cert is NOT bound to the uploader's JWT. Stage-2 attestation already
// forces signing with the device's own enrolled key, so a JWT binding would
// buy nothing and would break legitimate cross-user re-shares. The
// enrollment-time user_id↔key_id link (read at revoke time, not here) is
// what abuse tooling maps an offending cert → account by.
//
// Both the signing-key lookup and the nonce burn key on
// signature_info.cert_serial_number: c2pa-node v0.5.5's Reader does not
// expose the leaf cert bytes via the public API but does expose the serial
// directly, and our CA mints a fresh random serial per leaf, so it is
// equivalently unique.

import { VerifyError, VerifyErrorCode } from "../errors.js";
import { postgresAdapter, type RevocationRow } from "../db.js";
import type { VerifierDatastore } from "../ports.js";
import { sanitizeManifestStore, type SanitizedManifestStore } from "../sanitize.js";
import {
  type ManifestStoreShape,
  type ManifestShape,
  getActiveManifest,
} from "../c2pa-shape.js";
import {
  classifyStrictValidationStatus,
  enforceActionsAllowlist,
  enforceFreshCaptureStage1,
  enforceStage2Parent,
  resolveCaptureThroughUpdateManifests,
  CAPTURE_ALLOWED_ACTIONS,
  REALREEL_UPLOAD_ALLOWED_ACTIONS,
} from "./_shared.js";
import {
  consumeAppAttestForStage,
  hasAppAttestAssertion,
  validateAppAttestStructure,
  type AppAttestCryptoInputs,
} from "../attestation/apple.js";
import {
  consumePlayIntegrityForStage,
  hasPlayIntegrityAssertion,
  validatePlayIntegrityStructure,
} from "../attestation/play_integrity.js";
import type { PlayIntegrityConfig } from "../config.js";

/**
 * @param sourceId The trust-source id resolved by identifyTrustSource()
 *   in verify.ts. Threaded through so the persisted c2pa_manifest row
 *   records exactly which trust-sources.yaml entry handled this
 *   manifest — not the hardcoded literal "realreel". Allows future
 *   multi-source-with-same-profile setups (e.g. a transitional second
 *   RealReel root for CA rotation) without mislabeling rows.
 * @param playIntegrityConfig Optional config for the Android Play
 *   Integrity validator. When undefined, Android manifests pass through
 *   leniently (structural envelope accepted, JWS decode skipped).
 *   Production sets it via PLAY_INTEGRITY_PACKAGE_NAME +
 *   PLAY_INTEGRITY_CLOUD_PROJECT_NUMBER env vars (see config.ts).
 * @param attestationRequired When true, missing Stage 2 per-upload
 *   attestation is a hard reject (ATTESTATION_MISSING) per the stage's
 *   signing-key platform (iOS → app_attest, Android → play_integrity).
 *   When false, the lenient gate applies: validate-if-present,
 *   accept-if-absent. Production ATTESTATION_REQUIRED=true; local dev
 *   leaves unset.
 * @param datastore Storage adapter for the revocation lookup + attestation
 *   nonce burn (see src/ports.ts). Defaults to the Postgres-backed
 *   `postgresAdapter`; injected from verify() so an OSS integrator can swap
 *   the backend.
 */
export async function verifyRealReel(
  storeUnknown: unknown,
  sourceId: string,
  playIntegrityConfig?: PlayIntegrityConfig,
  attestationRequired: boolean = false,
  datastore: VerifierDatastore = postgresAdapter,
): Promise<SanitizedManifestStore> {
  const store = storeUnknown as ManifestStoreShape;

  // Surface c2pa-node validation issues as hard rejects. The codes c2pa-rs
  // emits are documented in C2PA §15.6; we bucket them into our four codes
  // (CERT_EXPIRED, SIGNATURE_INVALID, MANIFEST_MALFORMED, UNTRUSTED_ISSUER).
  // Because this throws on any issue, sanitizeManifestStore() is only ever
  // reached with an empty validation_status, so persisted realreel rows are
  // always validation_state 'trusted'.
  classifyStrictValidationStatus(store.validation_status ?? []);

  // active_manifest is a LABEL string in c2pa-node v0.5.5; resolve the object.
  const active = getActiveManifest(store);
  if (!active) {
    throw new VerifyError(
      VerifyErrorCode.MANIFEST_MALFORMED,
      "no active manifest",
    );
  }

  // Stage 2 = active manifest. Its lone ingredient is the parentOf — for a
  // never-offline upload that's the Stage-1 capture directly; for an upload of
  // a once-offline-then-TSA-drained asset it's an interposed timestamp Update
  // Manifest (chain: Stage-2 → Update → Stage-1). The parentOf structural rule
  // (exactly one ingredient, relationship parentOf) rejects composites,
  // single-stage files, and non-parentOf relationships. Pure check lives in
  // @realreel/c2pa-trust-core/policies/structure; this wrapper maps failure
  // reasons onto the verifier's VerifyError codes.
  const { parent: immediateParent } = enforceStage2Parent(store, active);

  // Walk PAST any interposed timestamp Update Manifest(s) to the real capture
  // (no-op on the common never-offline path). Each Update Manifest is
  // validated en route; per _shared.ts, the interposition can only add a
  // timestamp, never an edit.
  const capture = resolveCaptureThroughUpdateManifests(store, immediateParent);

  // Stage 1 structural rules — issuer-agnostic. A wrap-mode third-party
  // capture (Pixel etc.) must still be a fresh capture with only c2pa.created;
  // otherwise it's an edited photo masquerading as a trusted-camera source.
  enforceFreshCaptureStage1(capture);
  enforceActionsAllowlist(capture, CAPTURE_ALLOWED_ACTIONS, "Stage 1");

  // Stage 2 (active) actions must be a subset of the upload-stage allowlist
  // (compression, rotation, EXIF re-injection). All structural checks run
  // before any DB lookup, so a malformed manifest never hits the registry.
  enforceActionsAllowlist(active, REALREEL_UPLOAD_ALLOWED_ACTIONS, "Stage 2");

  // === Stage 1 (parent, the capture) revocation denylist ===
  // Revocation is dual-stage: denylisting a CAPTURE key kills every upload
  // that references it, by anyone — the kill switch for a signing oracle
  // whose fakes other accounts launder. DENYLIST semantics: reject ONLY if
  // the Stage-1 leaf serial is a known, revoked RealReel key. A serial absent
  // from the registry is fine — a wrap-mode parent (Pixel etc.) carries a
  // non-RealReel cert that was never enrolled, so the Stage-1 denylist only
  // bites native RealReel captures. We read solely revoked_at; the row's
  // user_id is never bound. Runs before the Stage 2 lookup.
  const stage1Serial = readCertSerial(capture, "stage 1");
  const stage1Row = await datastore.lookup(stage1Serial);
  // The row-present guard implements the denylist skip (not-found is not a
  // rejection); `revoked_at !== null` then fails CLOSED — a future undefined
  // (projection change / hand-built mock) reads as revoked rather than
  // silently slipping through.
  if (stage1Row && stage1Row.revoked_at !== null) {
    throw new VerifyError(
      VerifyErrorCode.KEY_REVOKED,
      `stage 1 capture key revoked at ${stage1Row.revoked_at}`,
    );
  }

  // === Stage 2 (active, the upload) signing-key lookup + gates ===
  // Stage 2 is RealReel-signed in both native + wrap modes. Its leaf cert
  // serial keys the user_signing_keys lookup.
  const stage2Serial = readCertSerial(active, "stage 2");
  const stage2Row = await datastore.lookup(stage2Serial);
  if (!stage2Row) {
    throw new VerifyError(
      VerifyErrorCode.KEY_NOT_FOUND,
      `stage 2 cert_serial_number not in user_signing_keys`,
    );
  }
  if (stage2Row.revoked_at !== null) {
    throw new VerifyError(
      VerifyErrorCode.KEY_REVOKED,
      `stage 2 signing key revoked at ${stage2Row.revoked_at}`,
    );
  }

  // Resolve the Stage 2 envelope STRUCTURE first (cheap), before any nonce
  // is burned. Stage 2 attestation is the upload-time proof:
  //   * iOS: org.realreel.app_attest — Apple cryptographic chain check.
  //   * Android: org.realreel.play_integrity — full JWS decode (verdicts
  //     PLAY_RECOGNIZED + MEETS_STRONG_INTEGRITY). Play Integrity is
  //     online-only and catches post-boot runtime tampering.
  const stage2Envelope = resolveStageEnvelope(
    active,
    stage2Row.platform,
    "Stage 2",
    attestationRequired,
  );

  // Burn Stage 2's single-use nonce LAST — only after every other check has
  // passed (defeats bit-for-bit replay of the upload manifest).
  if (stage2Envelope?.kind === "app_attest") {
    const cryptoInputs = cryptoInputsForRow(stage2Row);
    // iOS App Attest is only meaningful when verified against the
    // enrollment-stored credCert pubkey. A row lacking it (or the SE SPKI)
    // is an enrollment/data error — reject unconditionally. There is NO
    // nonce-only fallback: verification is local ECDSA (no external API), so
    // a bypass-on-missing-pubkey path would be a dead security shortcut. The
    // DB enforces the same invariant via a NOT NULL constraint.
    if (cryptoInputs === null) {
      throw new VerifyError(
        VerifyErrorCode.ATTESTATION_INVALID,
        "Stage 2 iOS signing key has no enrollment-stored App Attest public key — cannot verify the assertion",
      );
    }
    await consumeAppAttestForStage(
      stage2Envelope.data,
      stage2Row.key_id,
      "Stage 2",
      cryptoInputs,
      datastore,
    );
  } else if (stage2Envelope?.kind === "play_integrity") {
    await consumePlayIntegrityForStage(
      stage2Envelope.data,
      stage2Row.key_id,
      "Stage 2",
      playIntegrityConfig,
      datastore,
    );
  }

  return sanitizeManifestStore(storeUnknown, sourceId);
}

/**
 * Pull signature_info.cert_serial_number from a manifest, with a clear
 * error if missing. The verifier requires this field — c2pa-node
 * populates it for every signed manifest; absence means the manifest
 * is malformed or c2pa-node's API changed.
 */
function readCertSerial(manifest: ManifestShape, stageLabel: string): string {
  const serial = manifest.signature_info?.cert_serial_number;
  if (typeof serial !== "string" || serial.length === 0) {
    throw new VerifyError(
      VerifyErrorCode.MANIFEST_MALFORMED,
      `${stageLabel} signature_info.cert_serial_number missing`,
    );
  }
  return serial;
}

/**
 * Discriminated result of structural envelope resolution. Splitting
 * resolution from the consume step preserves the structural-then-consume
 * ordering (validate the shape before burning the nonce).
 */
type StageEnvelope =
  | {
      kind: "app_attest";
      data: ReturnType<typeof validateAppAttestStructure>;
    }
  | {
      kind: "play_integrity";
      data: ReturnType<typeof validatePlayIntegrityStructure>;
    };

/**
 * Pick + validate the Stage-2 attestation envelope, honoring the
 * strict-vs-lenient policy and per-platform requirements.
 *
 * Behavior:
 *   * Stage carries BOTH envelopes → ATTESTATION_INVALID (manifest
 *     stuffing or build bug; reject before burning either nonce).
 *   * required AND iOS platform AND missing app_attest → ATTESTATION_MISSING.
 *   * required AND android platform AND missing play_integrity →
 *     ATTESTATION_MISSING.
 *   * required AND unknown platform → ATTESTATION_INVALID (defensive;
 *     the CHECK constraint on user_signing_keys.platform should prevent it).
 *   * Stage has the envelope matching its platform → return the parsed
 *     structure for the caller to consume.
 *   * Stage has an envelope NOT matching its platform (e.g., iOS-enrolled
 *     key carrying play_integrity) → ATTESTATION_INVALID. Catches a
 *     tampered build or a key/manifest mismatch.
 *   * NOT required AND envelope absent → return null (lenient path).
 */
function resolveStageEnvelope(
  manifest: ManifestShape,
  platform: string,
  stageLabel: string,
  attestationRequired: boolean,
): StageEnvelope | null {
  const hasApp = hasAppAttestAssertion(manifest);
  const hasPlay = hasPlayIntegrityAssertion(manifest);

  if (hasApp && hasPlay) {
    throw new VerifyError(
      VerifyErrorCode.ATTESTATION_INVALID,
      `${stageLabel} carries both app_attest and play_integrity assertions`,
    );
  }

  // Anything outside the known set is "unknown"; the schema's CHECK
  // constraint should prevent it, but the verifier does not assume so.
  const isIos = platform === "ios";
  const isAndroid =
    platform === "android-strongbox" || platform === "android-tee";

  if (attestationRequired && !isIos && !isAndroid) {
    throw new VerifyError(
      VerifyErrorCode.ATTESTATION_INVALID,
      `${stageLabel} signing key has unrecognized platform '${platform}' — refusing to determine which envelope to require`,
    );
  }

  // Cross-platform envelope mismatch: an iOS-enrolled key signing a
  // manifest with play_integrity (or vice-versa) is always wrong. Reject
  // regardless of attestationRequired, rather than letting it slide into a
  // misrouted nonce burn.
  if (hasApp && isAndroid) {
    throw new VerifyError(
      VerifyErrorCode.ATTESTATION_INVALID,
      `${stageLabel} signing key is Android (${platform}) but manifest carries app_attest`,
    );
  }
  if (hasPlay && isIos) {
    throw new VerifyError(
      VerifyErrorCode.ATTESTATION_INVALID,
      `${stageLabel} signing key is iOS but manifest carries play_integrity`,
    );
  }

  if (hasApp) {
    return { kind: "app_attest", data: validateAppAttestStructure(manifest, stageLabel) };
  }
  if (hasPlay) {
    return {
      kind: "play_integrity",
      data: validatePlayIntegrityStructure(manifest, stageLabel),
    };
  }

  if (attestationRequired) {
    const expected = isIos ? "app_attest" : "play_integrity";
    throw new VerifyError(
      VerifyErrorCode.ATTESTATION_MISSING,
      `${stageLabel} signing key is '${platform}' but manifest lacks ${expected}`,
    );
  }

  return null;
}

/**
 * Assemble the cryptographic inputs the App Attest validator needs: the
 * enrollment-stored App Attest credCert pubkey + the SE SPKI. Returns null
 * when either is missing, so the caller rejects (an App Attest assertion
 * can't be verified without the stored pubkey, and there is no nonce-only
 * fallback). A NOT NULL DB constraint makes a null unrepresentable.
 */
function cryptoInputsForRow(row: RevocationRow): AppAttestCryptoInputs | null {
  if (!row.app_attest_public_key || !row.public_key) return null;
  return {
    appAttestPublicKey: new Uint8Array(row.app_attest_public_key),
    signingKeySpki: new Uint8Array(row.public_key),
  };
}
