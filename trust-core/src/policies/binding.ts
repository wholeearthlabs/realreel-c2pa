// Hard-binding policy — "were the capture's BYTES actually verified against
// its signed hash." Pure functions shared by the client preflight gate and
// the server verifier so they can't disagree.
//
// Editing an asset's bytes breaks its hard binding (`c2pa.hash.data` /
// `c2pa.hash.bmff.*`) while leaving the claim SIGNATURE valid — the
// signature covers the claim, not the pixels. The binding can only be
// checked by whoever holds the ORIGINAL bytes:
//
//   * The CLIENT gate holds them (the just-picked file): its anchorless
//     reader reports binding failures in store-level validation_status;
//     findContentTamperCodes filters out the trust-config noise.
//   * The SERVER never holds them — upload transforms replace the parent's
//     bytes. The sole surviving carrier of the verdict is the sign-time
//     report photo-attest records into the Stage-2 `c2pa.ingredient.v3`
//     assertion; findRecordedBindingViolation judges it and the verifier
//     rejects violations (PARENT_BINDING_FAILED). Trust footing: same as
//     the declared action list — honest in a genuine build, underwritten by
//     the per-upload platform attestation.

import type {
  IngredientShape,
  ManifestStoreShape,
  ValidationStatusEntryShape,
} from "../shapes/manifest.js";

// ⚠️ KNOWN LIMITATION (accepted; enforcement stays unconditional): released
// c2pa mobile SDKs (c2pa-ios ≤ 0.0.12, c2pa-android ≤ 0.0.10) predate
// c2pa-rs PR #2434 ("Support Xpath indices", 2026-08-09) and compute a FALSE
// `assertion.bmffHash.mismatch` for Google Pixel videos, whose
// `c2pa.hash.bmff.v3` exclusions use an indexed xpath (`/moov[1]/trak[3]`)
// pre-#2434 engines silently fail to resolve. So wrap-mode Pixel VIDEOS —
// genuine and tampered alike — are rejected until photo-attest and the app's
// reader bump to an SDK containing the fix: content we cannot verify is
// content we do not accept. Acceptance then restores itself (clean recorded
// verdicts simply pass; nothing to flip). RealReel's own BMFF captures use
// c2pa-rs's default non-indexed exclusions and verify correctly today;
// photos are unaffected entirely.

/** validation-code prefixes that speak to a hard binding (any family we
 * could ever meet; boxes/collection included defensively). */
const BINDING_CODE_PREFIXES = [
  "assertion.dataHash.",
  "assertion.bmffHash.",
  "assertion.boxesHash.",
  "assertion.collectionHash.",
] as const;

/** Explicit binding FAILURE suffixes. Suffix-matched (not "anything that
 * isn't `.match`") because c2pa-rs also emits ADVISORY binding codes —
 * `assertion.dataHash.additionalExclusionsPresent` rides in every Pixel
 * photo's recorded report — and sweeping those in would hard-reject genuine
 * media if a future SDK ever re-buckets them. Unknown failure spellings are
 * still caught by the positive-proof requirement in
 * findRecordedBindingViolation. */
const BINDING_FAILURE_SUFFIXES = [
  ".mismatch",
  ".missing",
  ".malformed",
  ".invalid",
] as const;

/** True iff `code` is a hard-binding validation code (either polarity). */
export function isBindingCode(code: string): boolean {
  return BINDING_CODE_PREFIXES.some((p) => code.startsWith(p));
}

/** Entries → code strings, dropping malformed entries (native JSON is an
 * unchecked cast; a null entry or non-string code must not throw out of the
 * gate). */
function validCodes(
  entries: ValidationStatusEntryShape[] | undefined,
): string[] {
  return (entries ?? [])
    .map((e) => e?.code)
    .filter((code): code is string => typeof code === "string");
}

/** Filter a validation entry list down to hard-binding FAILURE codes. */
export function findBindingFailureCodes(
  entries: ValidationStatusEntryShape[] | undefined,
): string[] {
  return validCodes(entries).filter(
    (code) =>
      isBindingCode(code) &&
      BINDING_FAILURE_SUFFIXES.some((s) => code.endsWith(s)),
  );
}

/**
 * CLIENT-side tamper filter for a freshly-read file's store-level
 * validation_status. DENYLIST shape so unknown codes fail CLOSED: the array
 * only ever carries failure-bucket codes, and the anchorless client reader's
 * benign set is small and closed — `signingCredential.*` /
 * `timeStamp.untrusted` (no trust anchors configured) plus advisory
 * binding notes and positive proofs, should they ever leak in. Everything
 * else is treated as tamper.
 */
export function findContentTamperCodes(
  entries: ValidationStatusEntryShape[] | undefined,
): string[] {
  return validCodes(entries).filter(
    (code) =>
      !code.startsWith("signingCredential.") &&
      code !== "timeStamp.untrusted" &&
      !code.endsWith(".additionalExclusionsPresent") &&
      !code.endsWith(".match"),
  );
}

/** Discriminated failure cases for findRecordedBindingViolation. Stable
 * `reason` strings; `detail` is human-readable and safe for server response
 * bodies / Sentry tags. */
export type RecordedBindingViolation =
  | {
      /** No ingredient entry referencing the capture carries a sign-time
       * validation report. Every genuine RealReel Stage 2 records one
       * (photo-attest addIngredient), so absence means an old/foreign
       * builder — fail closed. */
      reason: "no_recorded_results";
      detail: string;
    }
  | {
      /** A report exists but its success bucket lacks a positive binding
       * proof. */
      reason: "match_missing";
      detail: string;
    }
  | {
      /** The report carries recorded hard-binding failures — the parent's
       * bytes did not match its signed hash at Stage-2 sign time. */
      reason: "binding_failure";
      detail: string;
      failureCodes: string[];
    };

/**
 * Judge the SIGN-TIME binding verdict recorded for the capture manifest.
 *
 * Scans every manifest's ingredients for entries referencing the capture's
 * label — the Stage-2 parentOf entry in the common shape; the Update
 * Manifest's entry in the offline-TSA-drained chain (an UM carries no
 * binding of its own, so the capture reference is what matters). Every
 * referencing entry must carry a report with at least one positive binding
 * proof (`assertion.*Hash.match`, any family — the genuine SDK picks the
 * family; requiring a specific one buys nothing against a hostile build and
 * would hard-reject e.g. BMFF stills) and no binding failure. First
 * violation wins.
 *
 * Pure judgment — callers map violations onto their error domain (server:
 * PARENT_BINDING_FAILED). See the known-limitation note above.
 */
export function findRecordedBindingViolation(
  store: ManifestStoreShape,
  captureLabel: string,
): RecordedBindingViolation | null {
  const referencingEntries: IngredientShape[] = [];
  for (const manifest of Object.values(store.manifests ?? {})) {
    for (const ingredient of manifest.ingredients ?? []) {
      if (ingredient.active_manifest === captureLabel) {
        referencingEntries.push(ingredient);
      }
    }
  }

  if (referencingEntries.length === 0) {
    return {
      reason: "no_recorded_results",
      detail: `no ingredient entry references capture '${captureLabel}'`,
    };
  }

  for (const entry of referencingEntries) {
    const recorded = entry.validation_results?.activeManifest;
    if (!recorded) {
      return {
        reason: "no_recorded_results",
        detail:
          "capture ingredient carries no sign-time validation report " +
          "(validation_results absent)",
      };
    }

    const failureCodes = findBindingFailureCodes(recorded.failure);
    if (failureCodes.length > 0) {
      return {
        reason: "binding_failure",
        detail: `recorded hard-binding failure(s): ${failureCodes.join(", ")}`,
        failureCodes,
      };
    }

    const hasMatch = validCodes(recorded.success).some(
      (code) => isBindingCode(code) && code.endsWith(".match"),
    );
    if (!hasMatch) {
      return {
        reason: "match_missing",
        detail:
          "recorded results lack a positive binding proof (assertion.*Hash.match)",
      };
    }
  }

  return null;
}
