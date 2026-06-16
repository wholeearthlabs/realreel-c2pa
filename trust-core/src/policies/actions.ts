// Action-allowlist policy. Pure functions over a parsed ManifestShape —
// no I/O, no error-class dependency. Both the Cloud Run verifier (server)
// and the React Native client preflight gate consume these. Server-side
// callers wrap a non-null violation in a VerifyError(SIGNATURE_INVALID);
// client-side callers map it to an EDITED ClientGateReason.
//
// Why these specific actions:
//
// CAPTURE_ALLOWED_ACTIONS — what a "fresh capture" manifest is permitted to
// declare. For Pixel / single-stage: the active manifest IS the capture. For
// realreel: this is Stage 1 (the parent ingredient). Only c2pa.created is
// allowed — anything else implies an edit. digitalSourceType variations
// (digitalCapture, computationalCapture, etc.) are NOT checked here — they're
// informational metadata about the camera type, not edit indicators.
//
// REALREEL_UPLOAD_ALLOWED_ACTIONS — Stage 2 (upload-time re-sign), recording
// the upload-time transformations applied by the app's upload path. The list
// MUST match the emit-side wiring (the native Stage2Action
// union and the per-path emission in the app's upload path), plus the
// `c2pa.opened` that c2pa-rs auto-prepends for BuilderIntent.Edit. Anything
// outside this set is a hard reject (caught by the per-action roundtrip test
// in verifier/__tests__/policy.test.ts).
//
// Two concrete attacks the allowlist closes:
//   1. A C2PA-aware external editor (Google Photos, Photoshop) edits the
//      photo and re-signs with its own CA. The resulting manifest has
//      c2pa.opened + c2pa.adjustedColor (or similar) and a non-empty
//      ingredient chain. Without this allowlist, c2pa-rs would
//      cryptographically validate and accept it (if the editor's root were in
//      our trust bundle).
//   2. A tampered RealReel build hooked to apply filters pre-Stage-1 that
//      honestly records those actions in the manifest.
//
// What this DOESN'T catch: a tampered build that dishonestly omits the edit
// actions and emits a clean-looking manifest. Manifest-level structural
// integrity cannot distinguish "real capture" from "tampered capture that
// emits a clean manifest" — trust there rests on enrollment (the signing key
// chaining to a trusted hardware-backed root) plus Stage-2 app attestation.

import type { ManifestShape } from "../shapes/manifest.js";

/**
 * Action names allowed on a "fresh capture" manifest. Only c2pa.created.
 *
 * Used by both validators on the active manifest of a single-stage capture
 * (Pixel) and the Stage 1 parent ingredient of a RealReel two-stage upload.
 */
export const CAPTURE_ALLOWED_ACTIONS: ReadonlySet<string> = new Set([
  "c2pa.created",
]);

/**
 * Action names allowed on RealReel's Stage 2 (upload-time re-sign).
 * See file header for the emit-side cross-reference + the rationale for
 * each entry.
 */
export const REALREEL_UPLOAD_ALLOWED_ACTIONS: ReadonlySet<string> = new Set([
  "c2pa.opened", //   auto-injected by c2pa-rs for BuilderIntent.Edit
  "c2pa.rotated", //  user-requested rotation correction
  "c2pa.resized", //  user-requested compression (photo path: 1080px max)
  "c2pa.transcoded", // user-requested codec/quality change
  "c2pa.cropped", //  user-requested crop (not in app yet, but type-allowed)
  "c2pa.trimmed", //  user-requested video trim (video path default)
  "c2pa.redacted", // user-requested location redaction
]);

/** A single well-formed action entry: the action name plus its raw, opaque
 *  parameters (shape varies per action — e.g. c2pa.trimmed carries {start,end}).
 */
export interface ActionEntry {
  action: string;
  parameters?: unknown;
}

/**
 * Walk EVERY c2pa.actions / .v2 assertion on the manifest and return each
 * well-formed action entry (name + raw parameters), in document order across
 * all such assertions (multiple are spec-discouraged but possible; collecting
 * all avoids silently dropping one). Array.isArray-guarded against a malformed
 * `actions: "string"` shape; entries without a non-empty string `action` are
 * skipped. The single source of the actions-iteration logic — extractManifestActions
 * (names only) and content-hash's extractContentExtent (names + params) both build on it.
 */
export function extractActionEntries(manifest: ManifestShape): ActionEntry[] {
  const out: ActionEntry[] = [];
  for (const assertion of manifest.assertions ?? []) {
    if (
      assertion.label !== "c2pa.actions.v2" &&
      assertion.label !== "c2pa.actions"
    ) {
      continue;
    }
    const data = assertion.data as { actions?: unknown } | null;
    if (!data || !Array.isArray(data.actions)) continue;
    for (const a of data.actions) {
      const action = (a as { action?: unknown })?.action;
      if (typeof action === "string" && action.length > 0) {
        out.push({ action, parameters: (a as { parameters?: unknown })?.parameters });
      }
    }
  }
  return out;
}

/**
 * Extract the union of action names from EVERY c2pa.actions / .v2 assertion
 * on the manifest. Returns empty when no well-formed actions assertion is
 * present. (Names only — see extractActionEntries for names + parameters.)
 */
export function extractManifestActions(manifest: ManifestShape): string[] {
  return extractActionEntries(manifest).map((e) => e.action);
}

/**
 * Discriminated result of an allowlist check. Caller chooses whether
 * to throw (server) or surface a structured rejection (client).
 */
export interface ActionViolation {
  /** Disallowed action names that were found. Deduplicated; order is
   * stable to insertion order so error messages read deterministically. */
  disallowed: string[];
}

/**
 * Pure allowlist check. Collects ALL disallowed actions (deduplicated) so
 * triage sees the full picture, not just the first. Returns null when every
 * action is allowed; `{ disallowed }` otherwise.
 */
export function findDisallowedActions(
  manifest: ManifestShape,
  allowlist: ReadonlySet<string>,
): ActionViolation | null {
  const actions = extractManifestActions(manifest);
  const disallowed = actions.filter((a) => !allowlist.has(a));
  if (disallowed.length === 0) return null;
  return { disallowed: Array.from(new Set(disallowed)) };
}
