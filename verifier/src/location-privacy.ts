// Location-privacy backstop. A working client puts GPS in BOTH the file bytes
// and the signed assertion (precise) or NEITHER (non-precise) — two independent
// client write-paths. This gate cross-checks the two artifacts the verifier
// already holds and rejects a leaking mismatch, so a strip regression can't
// reach the public bucket silently. No declared location level is needed:
// requiring the two paths to AGREE makes each the other's validator.
//
//   Direction 1 — bytes have GPS the assertion lacks: a non-precise upload whose
//     strip failed, leaking coordinates into the durable PUBLIC file. Hard
//     reject (fail closed) — the bytes are hash-bound, so we can't strip-and-keep
//     without breaking the signature.
//   Direction 2 — assertion has GPS the bytes lack: a display-surface leak, OR a
//     legit precise upload whose EXIF round-trip dropped (the signer's two paths
//     are independent by design). Indistinguishable, so SIGNAL, never reject.
//
// Residual: both paths regressing in lockstep reads as a consistent "precise"
// and passes; closing it needs the declared level (an unsigned request arg).

import { VerifyError, VerifyErrorCode } from "./errors.js";
import type { DerivedMetadata } from "./derive-metadata.js";

export interface LocationPrivacyResult {
  /** Direction 2 (see header): the caller signals telemetry, not a reject. */
  displayLeak: boolean;
}

/**
 * Throws VerifyError(LOCATION_PRIVACY_VIOLATION) on a Direction-1 file leak;
 * otherwise returns { displayLeak } for the caller to signal on.
 */
export function enforceLocationPrivacy(
  derived: DerivedMetadata,
): LocationPrivacyResult {
  const fileHasGps = derived.bytesHadGps;
  // coordPair() gates lat/lon both-or-neither, so checking both is belt-and-braces.
  const assertionHasGps = derived.latitude != null && derived.longitude != null;

  if (fileHasGps && !assertionHasGps) {
    throw new VerifyError(
      VerifyErrorCode.LOCATION_PRIVACY_VIOLATION,
      "uploaded bytes carry GPS absent from the signed manifest — a non-precise " +
        "upload leaked coordinates into the public file",
    );
  }

  return { displayLeak: assertionHasGps && !fileHasGps };
}
