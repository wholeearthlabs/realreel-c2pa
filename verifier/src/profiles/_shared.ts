// Profile-shared helpers for the realreel ingestion profile: a c2pa-rs
// validation-status classifier plus server-side wrappers that convert the
// pure policies from @realreel/c2pa-trust-core into thrown VerifyErrors.

import {
  findDisallowedActions,
  findRecordedBindingViolation,
  findUnverifiedRecordedFailures,
  getIngredientAssertionUri,
  isTimestampUpdateManifest,
  requireFreshCapture,
  resolveParentOfIngredient,
} from "@realreel/c2pa-trust-core";
import { VerifyError, VerifyErrorCode } from "../errors.js";
import type { ManifestShape, ManifestStoreShape } from "../c2pa-shape.js";
import type {
  ResolvedTrustSource,
  TrustSourceResolver,
} from "../trust/dispatcher.js";

export {
  CAPTURE_ALLOWED_ACTIONS,
  REALREEL_UPLOAD_ALLOWED_ACTIONS,
} from "@realreel/c2pa-trust-core";

const OCSP_CODE_PREFIX = "signingCredential.ocsp.";
const OCSP_NOT_REVOKED = "signingCredential.ocsp.notRevoked";
// The `url` c2pa-rs gives the entries it logs while checking a fetched
// response. A stapled response files its notRevoked under the signature URI.
const OCSP_FETCHED_RESPONSE_URL = "OCSP_RESPONSE";
const isFetchedNotRevoked = (e: { code: string; url?: string | null }): boolean =>
  e.code === OCSP_NOT_REVOKED && e.url === OCSP_FETCHED_RESPONSE_URL;

/** Starts the detail of a CERT_EXPIRED about a signature other than this
 *  upload's (the photo's capture or timestamp manifest), so the app can say
 *  retrying won't help instead of re-enrolling. App-facing format, pinned by
 *  tests. */
export const CAPTURE_CERT_EXPIRED_DETAIL_PREFIX = "capture: ";

/**
 * Map a c2pa-rs validation_status array to our VerifyError taxonomy.
 * Strict: every non-empty status is a hard reject.
 *
 * C2PA validation status codes (see C2PA §15.6):
 *   - signingCredential.ocsp.revoked / .unknown, anywhere in the array
 *                                 → UNTRUSTED_ISSUER (never KEY_REVOKED: that
 *                                   code makes the app discard the uploader's
 *                                   own key, and a revoked wrap-mode parent
 *                                   is another camera's certificate)
 *   - signingCredential.expired   → CERT_EXPIRED, also when the first entry is
 *                                   untrusted for the same signature: c2pa-rs
 *                                   0.91 checks the chain's validity in its
 *                                   trust check, which it logs first. When the
 *                                   expired signature isn't in
 *                                   `activeManifestLabel` (this upload's own
 *                                   manifest), the detail starts with
 *                                   CAPTURE_CERT_EXPIRED_DETAIL_PREFIX
 *   - signingCredential.untrusted → UNTRUSTED_ISSUER
 *   - claimSignature.* / *.mismatch / *.invalid → SIGNATURE_INVALID
 *   - manifest.* + everything else → MANIFEST_MALFORMED
 */
export function classifyStrictValidationStatus(
  status: Array<{ code: string; explanation?: string | null; url?: string | null }>,
  activeManifestLabel?: string,
): void {
  // INVARIANT (pinned by classify-validation-status.test.ts): this throws on
  // ANY non-empty validation status. Apart from revocation, only status[0]
  // is classified into a specific code, but the catch-all `else` below
  // guarantees a non-empty array can never be accepted — so a real failure
  // at status[1+] can't slip through. Do NOT add a tolerant branch that
  // returns without throwing on a non-empty status.
  const v = status[0];
  if (!v) return;
  const ocsp = status.find((s) => s.code.startsWith(OCSP_CODE_PREFIX));
  if (ocsp) {
    throw new VerifyError(
      VerifyErrorCode.UNTRUSTED_ISSUER,
      ocsp.explanation ? `${ocsp.code}: ${ocsp.explanation}` : ocsp.code,
      { category: "ocsp" },
    );
  }
  const detail = v.explanation ?? v.code;
  const certExpired = (s: typeof v) => {
    const aboutUpload =
      activeManifestLabel === undefined ||
      typeof s.url !== "string" ||
      s.url.startsWith(`self#jumbf=/c2pa/${activeManifestLabel}/`);
    const sDetail = s.explanation ?? s.code;
    return new VerifyError(
      VerifyErrorCode.CERT_EXPIRED,
      aboutUpload ? sDetail : `${CAPTURE_CERT_EXPIRED_DETAIL_PREFIX}${sDetail}`,
    );
  };
  if (v.code.startsWith("signingCredential.expired")) {
    throw certExpired(v);
  }
  if (v.code.startsWith("signingCredential.untrusted")) {
    const expired = status.find(
      (s) => s.code.startsWith("signingCredential.expired") && s.url === v.url,
    );
    if (expired) throw certExpired(expired);
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

/**
 * Resolve the Stage-1 CAPTURE's trust source and require a capture-capable
 * role. This makes `wrap_parent_only` an enforced profile: without it, any
 * cert chaining to ANY pooled anchor — including the general-purpose TSA
 * roots (see trust/types.ts) — would qualify as a "trusted camera" parent.
 *
 * Interposed timestamp Update Manifests get their own, stricter check
 * (RealReel sources only): see enforceUpdateManifestSigner.
 */
export function enforceParentTrustSource(
  capture: ManifestShape,
  resolveTrustSource: TrustSourceResolver,
): ResolvedTrustSource {
  const issuer = capture.signature_info?.issuer;
  if (typeof issuer !== "string" || issuer.length === 0) {
    throw new VerifyError(
      VerifyErrorCode.MANIFEST_MALFORMED,
      "stage 1 signature_info.issuer missing",
    );
  }
  const source = resolveTrustSource(
    issuer,
    capture.signature_info?.common_name,
  );
  if (!source) {
    throw new VerifyError(
      VerifyErrorCode.UNTRUSTED_ISSUER,
      `stage 1 issuer '${issuer}' does not match any configured capture trust source`,
    );
  }
  // Default-deny keeps a future non-capture profile from silently qualifying.
  if (source.profile !== "realreel" && source.profile !== "wrap_parent_only") {
    throw new VerifyError(
      VerifyErrorCode.UNTRUSTED_ISSUER,
      `stage 1 trust source '${source.id}' (profile '${source.profile}') is not a capture-capable source`,
    );
  }
  return source;
}

/**
 * Require the responder's `notRevoked` answer for the capture when its
 * source declares OCSP responders. `store` is the read that ran with OCSP
 * fetch on. c2pa-rs files an ingredient's revocation codes under the ingredient
 * assertion that references it (`validation_results.ingredientDeltas[]`,
 * keyed by assertion URI), so the capture's rows are found by URI rather
 * than by position, and the active manifest's own OCSP codes are never
 * consulted. Only a fetched answer counts: `notRevoked` in the `success`
 * bucket with the fetch's `url`. A response stapled into the COSE unprotected
 * header — writable by whoever assembles the upload, and it suppresses the
 * fetch — also files `notRevoked` as `success` since c2pa-rs 0.91, but under
 * the signature URI. A missing answer is VERIFIER_UNAVAILABLE, retryable; a
 * `revoked` answer is already rejected by classifyStrictValidationStatus.
 */
export function enforceParentRevocationStatus(
  store: ManifestStoreShape,
  capture: ManifestShape,
  source: ResolvedTrustSource,
): void {
  if (!source.revocation) return;
  const uris = captureIngredientAssertionUris(store, capture);
  const deltas = (store.validation_results?.ingredientDeltas ?? []).filter(
    (d) =>
      typeof d.ingredientAssertionURI === "string" &&
      uris.has(d.ingredientAssertionURI),
  );
  const seen: string[] = [];
  for (const delta of deltas) {
    const buckets = delta.validationDeltas ?? {};
    if ((buckets.success ?? []).some(isFetchedNotRevoked)) return;
    for (const bucket of ["success", "informational", "failure"] as const) {
      for (const e of buckets[bucket] ?? []) {
        if (typeof e.code === "string" && e.code.startsWith(OCSP_CODE_PREFIX)) {
          const unfetched = e.code === OCSP_NOT_REVOKED && !isFetchedNotRevoked(e);
          seen.push(`${bucket}:${e.code}${unfetched ? " (not fetched)" : ""}`);
        }
      }
    }
  }
  throw new VerifyError(
    VerifyErrorCode.VERIFIER_UNAVAILABLE,
    `stage 1 revocation status not confirmed by the '${source.id}' OCSP responder (OCSP codes seen: ${seen.length ? seen.join(", ") : "none"})`,
    { category: "ocsp" },
  );
}

/** The `ingredientAssertionURI`s under which c2pa-rs reports the capture's
 *  validation: every ingredient entry that references the capture's label,
 *  addressed by its holding manifest and assertion label. */
function captureIngredientAssertionUris(
  store: ManifestStoreShape,
  capture: ManifestShape,
): Set<string> {
  const uris = new Set<string>();
  if (typeof capture.label !== "string") return uris;
  for (const [holderLabel, manifest] of Object.entries(store.manifests ?? {})) {
    for (const ingredient of manifest.ingredients ?? []) {
      if (ingredient.active_manifest !== capture.label) continue;
      const uri = getIngredientAssertionUri(holderLabel, ingredient.label);
      if (uri !== null) uris.add(uri);
    }
  }
  return uris;
}

/**
 * Enforce the capture's HARD BINDING via the sign-time report recorded in
 * the Stage-2 `c2pa.ingredient.v3` assertion — the only carrier of that
 * verdict, since the parent's original bytes never reach the server.
 * Fail-closed and unconditional: an absent record, a missing positive
 * match, or a recorded binding failure is a reject. Design + the accepted
 * Pixel-video limitation: trust-core policies/binding.ts.
 */
export function enforceParentBinding(
  store: ManifestStoreShape,
  capture: ManifestShape,
): void {
  const captureLabel = capture.label;
  if (typeof captureLabel !== "string" || captureLabel.length === 0) {
    throw new VerifyError(
      VerifyErrorCode.MANIFEST_MALFORMED,
      "capture manifest has no label; cannot locate its recorded binding verdict",
    );
  }
  const violation = findRecordedBindingViolation(store, captureLabel);
  if (violation) {
    throw new VerifyError(
      VerifyErrorCode.PARENT_BINDING_FAILED,
      `Stage 1 hard binding not verified clean at sign time (${violation.reason}): ${violation.detail}`,
    );
  }
}

/**
 * Reject a recorded ingredient failure that c2pa-rs left out of
 * `validation_status`, classified as it would be live. See trust-core
 * policies/recorded-results.ts.
 */
export function enforceRecordedIngredientResults(
  store: ManifestStoreShape,
): void {
  // The recorded explanation is uploader-authored; the code alone is the detail.
  classifyStrictValidationStatus(
    findUnverifiedRecordedFailures(store).map((e) => ({ code: e.code, url: e.url })),
    store.active_manifest,
  );
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
// parentOf ingredient, and must be signed under a RealReel source: it carries
// the capture's recorded report, which the parent gates read, so only the
// draining app may write it. The capture beneath still faces the full
// fresh-capture + action-allowlist + revocation-denylist gates. Revocation is
// covered without a separate lookup here: the TSA queue is device-local, so
// the draining key IS the capturing key that the Stage-1 denylist already
// checks. If a future
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
 *  editorial action (Stage-2-allowlisted or not) stays disallowed, so the
 *  interposition still can't smuggle an edit. */
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
 * Throws VerifyError if an Update Manifest carries a disallowed action, isn't
 * signed under a RealReel source, its parent ingredient is malformed/dangling,
 * or the chain exceeds MAX_UPDATE_MANIFEST_DEPTH.
 */
export function resolveCaptureThroughUpdateManifests(
  store: ManifestStoreShape,
  immediateParent: ManifestShape,
  resolveTrustSource: TrustSourceResolver,
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
    enforceUpdateManifestSigner(current, resolveTrustSource);
    current = enforceUpdateManifestParent(store, current);
  }
  return current;
}

function enforceUpdateManifestSigner(
  updateManifest: ManifestShape,
  resolveTrustSource: TrustSourceResolver,
): void {
  const issuer = updateManifest.signature_info?.issuer;
  const source =
    typeof issuer === "string"
      ? resolveTrustSource(issuer, updateManifest.signature_info?.common_name)
      : null;
  if (source?.profile !== "realreel") {
    throw new VerifyError(
      VerifyErrorCode.UNTRUSTED_ISSUER,
      "interposed timestamp Update Manifest is not signed under a RealReel trust source",
    );
  }
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
