// Recorded ingredient results: the sign-time validation report that a
// `c2pa.ingredient.*` assertion carries for its parent.
//
// c2pa-rs drops a live ingredient finding from validation_status when the
// recorded report already lists it, so a parent failure the signer recorded
// never reaches the strict classifier. This recovers those failures.
//
// The signer's trust pool is narrower than the verifier's, so a recorded
// `signingCredential.*` failure can be a false alarm. When the verifier's own
// pool trusts the parent's chain, c2pa-rs reports `signingCredential.trusted`
// for it (unsuppressed, since the record disagrees), and that clears the
// parent's recorded `signingCredential.*` codes.

import {
  getIngredientAssertionUri,
  type ManifestStoreShape,
  type ValidationResultsBucketsShape,
  type ValidationStatusEntryShape,
} from "../shapes/manifest.js";
import { isBindingCode } from "./binding.js";

// The codes c2pa-rs `log_kind` classes as success or informational; it classes
// every other code as a failure whatever bucket a report files it in, so the
// code is judged here and the bucket ignored.
const NON_FAILURE_CODES: ReadonlySet<string> = new Set([
  "claimSignature.validated",
  "claimSignature.insideValidity",
  "signingCredential.trusted",
  "signingCredential.ocsp.notRevoked",
  "timeStamp.trusted",
  "timeStamp.validated",
  "assertion.hashedURI.match",
  "assertion.dataHash.match",
  "assertion.bmffHash.match",
  "assertion.accessible",
  "assertion.boxesHash.match",
  "assertion.collectionHash.match",
  "ingredient.manifest.validated",
  "ingredient.manifest.missing",
  "ingredient.claimSignature.validated",
  "signingCredential.ocsp.skipped",
  "signingCredential.ocsp.inaccessible",
  "timeStamp.untrusted",
  "timeStamp.outsideValidity",
  "timeStamp.mismatch",
  "timeStamp.malformed",
  "manifest.unknownProvenance",
  "algorithm.deprecated",
  "timeOfSigning.insideValidity",
  "ingredient.unknownProvenance",
  "assertion.dataHash.additionalExclusionsPresent",
]);

const SIGNING_CREDENTIAL_PREFIX = "signingCredential.";
const SIGNING_CREDENTIAL_TRUSTED = "signingCredential.trusted";

function bucketEntries(
  buckets: ValidationResultsBucketsShape | undefined,
): ValidationStatusEntryShape[] {
  if (!buckets) return [];
  return [
    ...(buckets.success ?? []),
    ...(buckets.informational ?? []),
    ...(buckets.failure ?? []),
  ];
}

/** Ingredient assertion URIs whose parent the verifier's own validation
 *  reports as `signingCredential.trusted`. */
function trustedParentUris(store: ManifestStoreShape): Set<string> {
  const uris = new Set<string>();
  for (const delta of store.validation_results?.ingredientDeltas ?? []) {
    const uri = delta?.ingredientAssertionURI;
    if (
      typeof uri === "string" &&
      (delta.validationDeltas?.success ?? []).some(
        (e) => e?.code === SIGNING_CREDENTIAL_TRUSTED,
      )
    ) {
      uris.add(uri);
    }
  }
  return uris;
}

/**
 * The failure codes recorded on any ingredient, minus hard-binding codes
 * (findRecordedBindingViolation's job) and minus `signingCredential.*` codes
 * on a parent the verifier itself trusts. Reads every bucket and the report's
 * own ingredient deltas, else the pre-v3 `validation_status`: the same
 * statuses c2pa-rs reconciles against.
 */
export function findUnverifiedRecordedFailures(
  store: ManifestStoreShape,
): ValidationStatusEntryShape[] {
  const trusted = trustedParentUris(store);
  const out: ValidationStatusEntryShape[] = [];
  for (const [holderLabel, manifest] of Object.entries(store.manifests ?? {})) {
    for (const ingredient of manifest.ingredients ?? []) {
      const uri = getIngredientAssertionUri(holderLabel, ingredient.label);
      const parentTrusted = uri !== null && trusted.has(uri);
      const results = ingredient.validation_results;
      const entries = results
        ? [
            ...bucketEntries(results.activeManifest),
            ...(results.ingredientDeltas ?? []).flatMap((d) =>
              bucketEntries(d?.validationDeltas),
            ),
          ]
        : (ingredient.validation_status ?? []);

      for (const entry of entries) {
        const code = entry?.code;
        if (typeof code !== "string") continue;
        if (NON_FAILURE_CODES.has(code) || isBindingCode(code)) continue;
        if (parentTrusted && code.startsWith(SIGNING_CREDENTIAL_PREFIX)) continue;
        out.push(entry);
      }
    }
  }
  return out;
}
