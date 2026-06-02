// Profile-shared helpers for the realreel ingestion profile: a c2pa-rs
// validation-status classifier plus server-side wrappers that convert the
// pure policies from @realreel/c2pa-trust-core into thrown VerifyErrors.

import {
  findDisallowedActions,
  isTimestampUpdateManifest,
  requireFreshCapture,
  resolveParentOfIngredient,
} from "@realreel/c2pa-trust-core";
import { VerifyError, VerifyErrorCode } from "../errors.js";
import type { ManifestShape, ManifestStoreShape } from "../c2pa-shape.js";

export {
  CAPTURE_ALLOWED_ACTIONS,
  REALREEL_UPLOAD_ALLOWED_ACTIONS,
} from "@realreel/c2pa-trust-core";

/**
 * Map a c2pa-rs validation_status array to our VerifyError taxonomy.
 * Strict: every non-empty status is a hard reject.
 *
 * C2PA validation status codes (see C2PA §15.6):
 *   - signingCredential.expired   → CERT_EXPIRED
 *   - signingCredential.untrusted → UNTRUSTED_ISSUER
 *   - claimSignature.* / *.mismatch / *.invalid → SIGNATURE_INVALID
 *   - manifest.* + everything else → MANIFEST_MALFORMED
 */
export function classifyStrictValidationStatus(
  status: Array<{ code: string; explanation?: string | null }>,
): void {
  // INVARIANT (pinned by classify-validation-status.test.ts): this throws on
  // ANY non-empty validation status. We only classify status[0] into a
  // specific code, but the catch-all `else` below guarantees a non-empty
  // array can never be accepted — so a real failure at status[1+] can't slip
  // through. Do NOT add a tolerant branch that returns without throwing on a
  // non-empty status.
  const v = status[0];
  if (!v) return;
  const detail = v.explanation ?? v.code;
  if (v.code.startsWith("signingCredential.expired")) {
    throw new VerifyError(VerifyErrorCode.CERT_EXPIRED, detail);
  }
  if (v.code.startsWith("signingCredential.untrusted")) {
    throw new VerifyError(VerifyErrorCode.UNTRUSTED_ISSUER, detail);
  }
  if (
    v.code.startsWith("claimSignature.") ||
    v.code.includes(".mismatch") ||
    v.code.includes(".invalid")
  ) {
    throw new VerifyError(VerifyErrorCode.SIGNATURE_INVALID, detail);
  }
  throw new VerifyError(VerifyErrorCode.MANIFEST_MALFORMED, detail);
}

/**
 * Reject the manifest if any action falls outside the allowlist. Throws
 * SIGNATURE_INVALID; the detail string lists every disallowed action. The
 * pure allowlist policy + constants live in
 * @realreel/c2pa-trust-core/policies/actions.
 */
export function enforceActionsAllowlist(
  manifest: ManifestShape,
  allowlist: ReadonlySet<string>,
  manifestLabel: string,
): void {
  const violation = findDisallowedActions(manifest, allowlist);
  if (violation) {
    throw new VerifyError(
      VerifyErrorCode.SIGNATURE_INVALID,
      `${manifestLabel} contains disallowed c2pa action(s): ${violation.disallowed.join(", ")}`,
    );
  }
}

// Structural-rule enforcement: wrappers mapping the pure structural rules in
// @realreel/c2pa-trust-core/policies/structure onto VerifyError codes.

/**
 * Stage 2 / parent-ingredient resolution. Returns `{ parent }` on success;
 * throws VerifyError on any structural failure. `dangling_parent_ref` →
 * MANIFEST_MALFORMED; every other reason → SIGNATURE_INVALID.
 */
export function enforceStage2Parent(
  store: ManifestStoreShape,
  active: ManifestShape,
): { parent: ManifestShape } {
  const result = resolveParentOfIngredient(store, active);
  if (result.ok) {
    return { parent: result.parent };
  }
  if (result.reason === "dangling_parent_ref") {
    throw new VerifyError(
      VerifyErrorCode.MANIFEST_MALFORMED,
      "RealReel manifest's parent ingredient references a missing manifest",
    );
  }
  throw new VerifyError(
    VerifyErrorCode.SIGNATURE_INVALID,
    `Stage 2 ${result.detail}`,
  );
}

/** Enforce fresh-capture structure on Stage 1. */
export function enforceFreshCaptureStage1(manifest: ManifestShape): void {
  const violation = requireFreshCapture(manifest);
  if (violation) {
    throw new VerifyError(
      VerifyErrorCode.SIGNATURE_INVALID,
      "Stage 1 must be a fresh capture with no ingredients",
    );
  }
}

// Interposed timestamp Update Manifest walk-through.
//
// An offline capture that's later timestamped (the app's offline-timestamp drain) gets an Update
// Manifest interposed between it and the eventual Stage-2 upload: the chain
// becomes Stage-2 → Update → Stage-1. The Update Manifest carries a
// `c2pa.time-stamp` assertion over the Stage-1 signature, signed by the
// device's own hardware key (c2pa-rs's auto_timestamp_assertion produces it —
// see "Trusted timestamps and offline verifiability" in
// TRUST_ARCHITECTURE.md). Without the walk below, enforceFreshCaptureStage1
// would see the Update Manifest as "Stage 1", find its parentOf ingredient, and
// reject — i.e. every once-offline upload would fail. So we walk PAST any
// interposed Update Manifest(s) to the real capture, on which the Stage-1 gates
// then run.
//
// Security: the interposition can only ADD a timestamp, never an edit. Each
// Update Manifest is gated to carry NO editorial action and exactly one
// parentOf ingredient; the capture beneath still faces the full fresh-capture +
// action-allowlist + revocation-denylist gates. Revocation is covered without a
// separate lookup here: the TSA queue is device-local, so the draining key IS
// the capturing key that the Stage-1 denylist already checks. If a future
// design ever let a queue entry drain on a DIFFERENT device than it was
// captured on, add a denylist lookup on each interposed Update Manifest's
// cert_serial here.
//
// ⚠️ TRUST OF THE TIMESTAMP ITSELF — NOT enforced here. This walk triggers on
// STRUCTURE only (presence of a `c2pa.time-stamp` assertion + ≥1 ingredient).
// It does NOT verify the token cryptographically or check it chains to a
// trusted TSA. That is safe today because the walk merely relocates the Stage-1
// gates onto the real capture (which still must pass everything), so a forged
// timestamp buys an attacker nothing. It becomes LOAD-BEARING the moment the
// verifier consumes a Stage-1 timestamp to accept an expired-leaf capture
// as-of-TSA-time: such a path MUST first require the interposed manifest's
// timestamp to be c2pa-rs-validated + trusted (the `timeStamp.trusted` state,
// today only surfaced for the active manifest) before granting any cert-expiry
// bypass — otherwise a forged assertion would confer an undeserved bypass.

/** An interposed Update Manifest may carry only `c2pa.opened` — which c2pa-rs
 *  auto-injects when it incorporates the Stage-1 parent from the source asset.
 *  `c2pa.opened` is "opened the parent," NOT an editorial transform — every
 *  editorial action (c2pa.resized / rotated / cropped / transcoded / trimmed)
 *  stays disallowed, so the interposition still can't smuggle an edit. */
const UPDATE_MANIFEST_ALLOWED_ACTIONS: ReadonlySet<string> = new Set([
  "c2pa.opened",
]);

/** Defensive cap on interposed Update Manifests — normally exactly one, but a
 *  re-stamp could add more. Bounds a crafted deep/cyclic chain. */
const MAX_UPDATE_MANIFEST_DEPTH = 4;

/**
 * Walk from Stage-2's immediate parent past any interposed timestamp Update
 * Manifest(s) and return the real capture manifest (on which the caller runs
 * the Stage-1 gates). When the immediate parent is already a fresh capture
 * (today's common, never-offline path), returns it unchanged.
 *
 * Throws VerifyError if an Update Manifest carries a disallowed action, its
 * parent ingredient is malformed/dangling, or the chain exceeds
 * MAX_UPDATE_MANIFEST_DEPTH.
 */
export function resolveCaptureThroughUpdateManifests(
  store: ManifestStoreShape,
  immediateParent: ManifestShape,
): ManifestShape {
  let current = immediateParent;
  let depth = 0;
  while (isTimestampUpdateManifest(current)) {
    if (++depth > MAX_UPDATE_MANIFEST_DEPTH) {
      throw new VerifyError(
        VerifyErrorCode.SIGNATURE_INVALID,
        `interposed timestamp Update Manifest chain exceeds depth ${MAX_UPDATE_MANIFEST_DEPTH}`,
      );
    }
    enforceUpdateManifestActions(current);
    current = enforceUpdateManifestParent(store, current);
  }
  return current;
}

/** The Update Manifest's lone parentOf ingredient. Mirrors enforceStage2Parent's
 *  failure mapping (dangling → MANIFEST_MALFORMED, else SIGNATURE_INVALID). */
function enforceUpdateManifestParent(
  store: ManifestStoreShape,
  updateManifest: ManifestShape,
): ManifestShape {
  const result = resolveParentOfIngredient(store, updateManifest);
  if (result.ok) return result.parent;
  if (result.reason === "dangling_parent_ref") {
    throw new VerifyError(
      VerifyErrorCode.MANIFEST_MALFORMED,
      "interposed timestamp Update Manifest's parent ingredient references a missing manifest",
    );
  }
  throw new VerifyError(
    VerifyErrorCode.SIGNATURE_INVALID,
    `interposed timestamp Update Manifest ${result.detail}`,
  );
}

function enforceUpdateManifestActions(updateManifest: ManifestShape): void {
  const violation = findDisallowedActions(
    updateManifest,
    UPDATE_MANIFEST_ALLOWED_ACTIONS,
  );
  if (violation) {
    throw new VerifyError(
      VerifyErrorCode.SIGNATURE_INVALID,
      `interposed timestamp Update Manifest contains disallowed action(s): ${violation.disallowed.join(", ")}`,
    );
  }
}
