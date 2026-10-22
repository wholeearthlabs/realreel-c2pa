// Recorded ingredient results: the sign-time validation report that a
// `c2pa.ingredient.*` assertion carries for its parent.
//
// c2pa-rs drops a live ingredient finding from validation_status when the
// recorded report already lists it, so a parent failure the signer recorded
// never reaches the strict classifier. This recovers those failures.
//
// The signer's trust pool is narrower than the verifier's, so a recorded
// `signingCredential.untrusted` or `.expired` can be a false alarm. When the
// verifier's own pool trusts the parent's chain, c2pa-rs reports
// `signingCredential.trusted` for it (unsuppressed, since the record
// disagrees), and that clears those two codes on the parent's own entries.

import {
  getIngredientAssertionUri,
  type ManifestStoreShape,
  type ValidationResultsBucketsShape,
  type ValidationStatusEntryShape,
} from "../shapes/manifest.js";
import { isBindingCode } from "./binding.js";

// The codes c2pa-rs `log_kind` classes as success or informational in any
// engine the phone or verifier runs; it classes every other code as a failure
// whatever bucket a report files it in, so the code is judged here and the
// bucket ignored. A code listed here never matches a live failure, so listing
// one a given engine doesn't know is safe.
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
  "assertion.bmffHash.additionalExclusionsPresent",
  "assertion.boxesHash.additionalExclusionsPresent",
  "signingCredential.ocsp.unknown",
  "cawg.x509.credential.trusted",
  "cawg.x509.signature.validated",
  "cawg.ica.untrusted_issuer",
]);

const SIGNING_CREDENTIAL_TRUSTED = "signingCredential.trusted";
const CLEARED_ON_TRUSTED_PARENT: ReadonlySet<string> = new Set([
  "signingCredential.untrusted",
  "signingCredential.expired",
]);

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

/** Per ingredient assertion URI, the urls the verifier's own validation
 *  reports as `signingCredential.trusted`. */
function liveTrustedUrls(store: ManifestStoreShape): Map<string, string[]> {
  const out = new Map<string, string[]>();
  for (const delta of store.validation_results?.ingredientDeltas ?? []) {
    const uri = delta?.ingredientAssertionURI;
    if (typeof uri !== "string") continue;
    for (const e of delta.validationDeltas?.success ?? []) {
      if (e?.code === SIGNING_CREDENTIAL_TRUSTED && typeof e.url === "string") {
        out.set(uri, [...(out.get(uri) ?? []), e.url]);
      }
    }
  }
  return out;
}

/**
 * The failure codes recorded on any ingredient, minus hard-binding codes
 * (findRecordedBindingViolation's job) and minus the untrusted/expired entries
 * about a parent the verifier itself trusts. Reads every bucket and the
 * report's own ingredient deltas, else the pre-v3 `validation_status`: the
 * same statuses c2pa-rs reconciles against.
 */
export function findUnverifiedRecordedFailures(
  store: ManifestStoreShape,
): ValidationStatusEntryShape[] {
  const liveTrusted = liveTrustedUrls(store);
  const out: ValidationStatusEntryShape[] = [];
  for (const [holderLabel, manifest] of Object.entries(store.manifests ?? {})) {
    for (const ingredient of manifest.ingredients ?? []) {
      const uri = getIngredientAssertionUri(holderLabel, ingredient.label);
      const parentUrl =
        typeof ingredient.active_manifest === "string"
          ? `self#jumbf=/c2pa/${ingredient.active_manifest}/`
          : null;
      const trustedParentUrl =
        parentUrl !== null &&
        uri !== null &&
        (liveTrusted.get(uri) ?? []).some((u) => u.startsWith(parentUrl))
          ? parentUrl
          : null;
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
        if (
          trustedParentUrl !== null &&
          CLEARED_ON_TRUSTED_PARENT.has(code) &&
          typeof entry.url === "string" &&
          entry.url.startsWith(trustedParentUrl)
        ) {
          continue;
        }
        out.push(entry);
      }
    }
  }
  return out;
}
