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
  /** Signing algorithm, e.g. "es256". Surfaced verbatim to viewers. */
  alg?: string;
  /** Signing time, ISO-8601. With sigTst2 this is the TSA token's `genTime`;
   * without it, the claim's internal signature time. Absent on legacy
   * manifests carrying neither. Read by the verifier's cert-validity gate. */
  time?: string;
  /** Some bindings surface the signing time as a Date instead of a string;
   * callers check `instanceof Date` before falling back to `time`. */
  timeObject?: Date;
}

/** Assertion entries inside manifest.assertions[]. The `data` payload is
 * opaque; downstream consumers walk known label values to surface fields. */
export interface AssertionShape {
  label?: string;
  data?: unknown;
}

/** One entry of a c2pa-rs validation report. The same shape appears in the
 * store-level `validation_status` array, in every `validation_results`
 * bucket, and in the sign-time report recorded inside a `c2pa.ingredient.v3`
 * assertion. */
export interface ValidationStatusEntryShape {
  code: string;
  explanation?: string | null;
  url?: string | null;
}

/** The three-bucket per-manifest validation report c2pa-rs emits under
 * claim v2 (C2PA §15.2.1). `success` carries positive proofs (e.g.
 * `assertion.dataHash.match`), `failure` carries hard rejections; entries in
 * `informational` are advisory only. */
export interface ValidationResultsBucketsShape {
  success?: ValidationStatusEntryShape[];
  informational?: ValidationStatusEntryShape[];
  failure?: ValidationStatusEntryShape[];
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
  /** Ingredient MIME type as recorded by the claim generator. Display-
   * informational; policy keys media kind off the capture's hard-binding
   * assertion label instead. */
  format?: string;
  /** The SIGN-TIME validation report recorded into the `c2pa.ingredient.v3`
   * assertion when the ingredient was added (C2PA §19.3). Once upload
   * transforms replace the parent's bytes, this is the ONLY artifact that
   * carries the parent's hard-binding verdict — later validators can't
   * recompute it and do NOT re-surface these entries into store-level
   * validation_status, so the verifier's parent-binding gate
   * (policies/binding.ts) reads them here explicitly. */
  validation_results?: {
    activeManifest?: ValidationResultsBucketsShape;
  };
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
  /** Aggregated FAILURES for the whole store (active manifest ∪ ingredient
   * deltas); `undefined` when nothing fatal. Blind spot the parent-binding
   * gate exists for: sign-time ingredient verdicts
   * (IngredientShape.validation_results) never land here. */
  validation_status?: ValidationStatusEntryShape[];
  /** "Trusted" | "Valid" | "Invalid" — display summary; consumers gate on
   * validation_status / validation_results instead. */
  validation_state?: string;
  /** Claim-v2 per-manifest report (C2PA §15.2.1): active manifest's three
   * buckets + per-ingredient deltas the validator computed itself (parent
   * cert trust etc. — never the parent's hard binding). */
  validation_results?: {
    activeManifest?: ValidationResultsBucketsShape;
    ingredientDeltas?: Array<{
      ingredientAssertionURI?: string;
      validationDeltas?: ValidationResultsBucketsShape;
    }>;
  };
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
