// Manifest structural rules. Pure functions — no I/O, no error class
// dependency. Both validators wrap a non-null violation in a domain-
// appropriate error (server: VerifyError; client: ClientGateResult), sharing
// the same structural logic so they can't disagree.

import type { ManifestShape, ManifestStoreShape } from "../shapes/manifest.js";

/** Result of a successful parent-ingredient resolution. */
export interface ParentResolution {
  ok: true;
  /** The C2PA label string that pointed at the parent — same string the
   * active manifest's ingredient.active_manifest field carries. */
  parentLabel: string;
  /** The parent manifest object, ready for further validation. */
  parent: ManifestShape;
}

/** Discriminated failure cases for resolveParentOfIngredient.
 *
 * The `reason` is a stable enum string. Server callers map specific
 * reasons to VerifyErrorCode (`dangling_parent_ref` →
 * MANIFEST_MALFORMED; everything else → SIGNATURE_INVALID); client
 * callers map them to ClientGateReason. The `detail` string is
 * human-readable + safe to surface in server response bodies / Sentry
 * tags. */
export type ParentResolutionFailure =
  | {
      ok: false;
      /** Active manifest has more than one ingredient. */
      reason: "too_many_ingredients";
      detail: string;
      /** Observed ingredient count, for telemetry. */
      ingredientCount: number;
    }
  | {
      ok: false;
      /** Active manifest has zero ingredients — caller required one. */
      reason: "no_ingredients";
      detail: string;
    }
  | {
      ok: false;
      /** Single ingredient present but its relationship isn't parentOf. */
      reason: "wrong_relationship";
      detail: string;
      /** Observed relationship value (may be undefined → "(missing)"). */
      observed: string;
    }
  | {
      ok: false;
      /** Ingredient parent label is absent OR points at a label that
       * isn't in the manifest store. */
      reason: "dangling_parent_ref";
      detail: string;
    };

/**
 * Validate Stage-2-style ingredient structure: exactly one ingredient,
 * `parentOf` relationship, label resolves to a manifest in the store.
 *
 * Returns the resolved parent on success, a structured failure
 * otherwise. Server uses MANIFEST_MALFORMED for `dangling_parent_ref`
 * (the manifest tree is internally inconsistent — a build / emitter
 * bug, not a user mistake) and SIGNATURE_INVALID for the other cases
 * (the manifest is well-formed but declares an edit chain we don't
 * accept).
 */
export function resolveParentOfIngredient(
  store: ManifestStoreShape,
  active: ManifestShape,
): ParentResolution | ParentResolutionFailure {
  const ingredients = active.ingredients ?? [];
  if (ingredients.length === 0) {
    return {
      ok: false,
      reason: "no_ingredients",
      detail: "must have exactly one ingredient (got 0)",
    };
  }
  if (ingredients.length !== 1) {
    return {
      ok: false,
      reason: "too_many_ingredients",
      detail: `must have exactly one ingredient (got ${ingredients.length})`,
      ingredientCount: ingredients.length,
    };
  }
  const ingredient = ingredients[0]!;
  if (ingredient.relationship !== "parentOf") {
    const observed = ingredient.relationship ?? "(missing)";
    return {
      ok: false,
      reason: "wrong_relationship",
      detail: `ingredient relationship must be 'parentOf' (got '${observed}')`,
      observed,
    };
  }
  const parentLabel = ingredient.active_manifest;
  if (!parentLabel) {
    return {
      ok: false,
      reason: "dangling_parent_ref",
      detail: "parent ingredient is missing active_manifest label",
    };
  }
  const parent = store.manifests?.[parentLabel];
  if (!parent) {
    return {
      ok: false,
      reason: "dangling_parent_ref",
      detail: `parent ingredient references a missing manifest (label='${parentLabel}')`,
    };
  }
  return { ok: true, parentLabel, parent };
}

/** Result of a failed fresh-capture check. Carries the labels of every
 * upstream ingredient so triage + Sentry tags can identify what
 * derivation chain was being claimed. Deduplicated; unlabeled ingredients
 * surface as the literal string "(unlabeled)" so message formatters can
 * print them inline. */
export interface FreshCaptureViolation {
  parentLabels: string[];
  ingredientCount: number;
}

/**
 * Validate "fresh capture" structure: the manifest has zero upstream
 * ingredients (realreel Stage 1 rejects any ingredient chain on the parent).
 * Returns null when the manifest is a fresh capture; otherwise the violation
 * with the parent labels (for telemetry).
 */
export function requireFreshCapture(
  manifest: ManifestShape,
): FreshCaptureViolation | null {
  const ingredients = manifest.ingredients ?? [];
  if (ingredients.length === 0) return null;
  return {
    parentLabels: ingredients.map((i) => i.active_manifest ?? "(unlabeled)"),
    ingredientCount: ingredients.length,
  };
}

/** Stage-2 upload-time attestation envelope labels. A correctly built client
 * emits exactly one platform's envelope on the Stage-2 (upload) manifest:
 * iOS → APP_ATTEST_LABEL, Android → PLAY_INTEGRITY_LABEL. The verifier's
 * realreel profile rejects a stage carrying both (manifest stuffing / build
 * bug) before any nonce burn. */
export const APP_ATTEST_LABEL = "org.realreel.app_attest";
export const PLAY_INTEGRITY_LABEL = "org.realreel.play_integrity";

/** Assertion label for a post-hoc RFC 3161 timestamp carried by an Update
 * Manifest (C2PA §11.2 / §10.3.2.5.4): a `HashMap<manifest_urn, token>` keyed
 * by the manifest whose COSE signature each token stamps.
 *
 * RealReel's offline TSA-drain produces exactly this — an Update Manifest
 * interposed between Stage-2 (upload) and Stage-1 (capture) carrying a trusted
 * timestamp over the Stage-1 signature, acquired when the device came back
 * online. Distinct from the inline `sigTst2` an ONLINE capture embeds in its
 * COSE unprotected HEADER — that is not an assertion and never appears here. */
export const TIMESTAMP_ASSERTION_LABEL = "c2pa.time-stamp";

/**
 * True iff `manifest` is an interposed timestamp Update Manifest: it carries a
 * `c2pa.time-stamp` assertion AND declares at least one upstream ingredient (so
 * it is not a fresh capture). RealReel's drain emits these between Stage-2 and
 * the Stage-1 capture; the verifier walks past them (validating each) to reach
 * the capture for the fresh-capture + action-allowlist + revocation gates.
 *
 * The ingredient requirement keeps a fresh capture from ever being mistaken
 * for an Update Manifest — a capture has no upstream ingredient. (An online
 * capture also carries its timestamp in the COSE sigTst2 header, not as a
 * `c2pa.time-stamp` assertion, so it is doubly safe from misfire.)
 */
export function isTimestampUpdateManifest(manifest: ManifestShape): boolean {
  const hasTimestamp = (manifest.assertions ?? []).some(
    (a) => a.label === TIMESTAMP_ASSERTION_LABEL,
  );
  if (!hasTimestamp) return false;
  return (manifest.ingredients ?? []).length > 0;
}
