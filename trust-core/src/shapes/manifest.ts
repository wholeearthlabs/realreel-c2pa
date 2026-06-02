// Narrow TypeScript shapes for the c2pa-rs JSON output. The same shape is
// emitted by every c2pa-rs binding — c2pa-node (server), c2pa-ios +
// c2pa-android (client native modules), c2pa-js (browser) — so it lives once
// here and both validators import it. End-to-end pinned against a real
// captured-then-uploaded RealReel JPEG by
// verifier/__tests__/verify-realreel.test.ts; a c2pa-node drift fails it
// loudly and the correction lands here.
//
// All fields are optional because the JS shape is permissive — c2pa-rs leaves
// fields undefined when the underlying assertion isn't present. Callers guard
// with explicit checks.

/** Minimal signature_info shape consumers read. `common_name` is the leaf
 * cert's subject CN as surfaced by c2pa-rs (e.g. "Pixel Camera"); used by
 * findTrustedIssuer to disambiguate a too-coarse issuer string. Typed
 * `string | undefined` even though c2pa-rs surfaces `string | null` — both
 * fail the exact-equality pin check identically. */
export interface SignatureInfoShape {
  issuer?: string;
  common_name?: string;
  cert_serial_number?: string;
}

/** Assertion entries inside manifest.assertions[]. The `data` payload is
 * opaque; downstream consumers walk known label values to surface fields. */
export interface AssertionShape {
  label?: string;
  data?: unknown;
}

/** Ingredient entries. The active_manifest field is a LABEL string pointing
 * into store.manifests, NOT a manifest object.
 *
 * `relationship` is the C2PA spec's enum of how this ingredient relates to
 * the current manifest:
 *   - "parentOf" — the manifest was derived from this ingredient
 *     (the canonical edit/upload case)
 *   - "componentOf" — this ingredient is a component of a composite
 *   - "inputTo" — this ingredient was an input to a generation step
 *     (e.g. AI prompt source)
 * The RealReel profile accepts `parentOf` only, for Stage 2's lone ingredient.
 */
export interface IngredientShape {
  active_manifest?: string;
  relationship?: string;
}

/** A single manifest within store.manifests[label]. */
export interface ManifestShape {
  label?: string;
  claim_generator?: string;
  title?: string;
  format?: string;
  signature_info?: SignatureInfoShape;
  assertions?: AssertionShape[];
  ingredients?: IngredientShape[];
}

/** c2pa-rs Reader output. Note: store.active_manifest is a LABEL STRING
 * pointing into store.manifests, NOT a nested manifest object — dereference
 * via store.manifests[active_manifest] (or getActiveManifest). */
export interface ManifestStoreShape {
  active_manifest?: string;
  manifests?: Record<string, ManifestShape>;
  validation_status?: Array<{
    code: string;
    explanation?: string | null;
    url?: string | null;
  }>;
}

/**
 * Resolve the active manifest object from a store. Centralized so the
 * label-vs-object distinction lives in one place.
 *
 * @returns the manifest object for store.active_manifest, or undefined if
 *   active_manifest is missing or points at a non-existent label.
 */
export function getActiveManifest(
  store: ManifestStoreShape,
): ManifestShape | undefined {
  const label = store.active_manifest;
  if (typeof label !== "string") return undefined;
  return store.manifests?.[label];
}
