// Location-privacy backstop — two layers that compose:
//
// (1) Declared-level check. The upload request carries the user's declared
//     location level (none | general | precise) as an UNSIGNED field. A
//     non-precise level is a privacy promise — publish no coordinates — so we
//     require NO GPS in EITHER artifact the verifier holds: the validated file
//     bytes AND the signed assertion. Either one present is a leak into a
//     durable public store, so we hard reject. Unsigned is safe here: the field
//     gates only the uploader's own coordinates and is never rendered as
//     provenance, so forging it only hurts the forger — there is no victim a
//     signature would protect. (A tampered build authors everything including
//     this field; that residual is the spine's job, layer 2.)
//
// (2) Bytes-vs-assertion spine (arg-independent). A working client puts GPS in
//     BOTH the file bytes and the signed assertion (precise) or NEITHER
//     (non-precise) via two independent write-paths. Requiring the two to AGREE
//     makes each the other's validator, so a single-path strip regression can't
//     reach the public bucket silently — even if the declared field is wrong,
//     forged, or its plumbing regresses.
//
//   Direction 1 — bytes have GPS the assertion lacks: a non-precise upload whose
//     strip failed, leaking coordinates into the durable PUBLIC file. Hard
//     reject (fail closed) — the bytes are hash-bound, so we can't strip-and-keep
//     without breaking the signature.
//   Direction 2 — assertion has GPS the bytes lack: a display-surface leak, OR a
//     legit precise upload whose EXIF round-trip dropped (the signer's two paths
//     are independent by design). Indistinguishable at the spine, so SIGNAL,
//     never reject.
//
// Layer (1) closes the spine's two blind spots once the level is known: a
// correlated double-regression (both paths leak, reading as a consistent
// "precise") and the Direction-2 assertion-only leak the spine can only signal.

import { VerifyError, VerifyErrorCode } from "./errors.js";
import type { DerivedMetadata } from "./derive-metadata.js";
import type { LocationLevel } from "@realreel/c2pa-trust-core";

export interface LocationPrivacyResult {
  /** Direction 2 (see header): the caller signals telemetry, not a reject. */
  displayLeak: boolean;
}

/**
 * Throws VerifyError(LOCATION_PRIVACY_VIOLATION) on a declared-level violation
 * (a non-precise upload carrying GPS in bytes OR assertion) or a Direction-1
 * file leak; otherwise returns { displayLeak } for the caller to signal on.
 *
 * Pure over (DerivedMetadata, declared) — no I/O, fully unit-testable.
 */
export function enforceLocationPrivacy(
  derived: DerivedMetadata,
  declared: LocationLevel,
): LocationPrivacyResult {
  const fileHasGps = derived.bytesHadGps;
  // coordPair() gates lat/lon both-or-neither, so checking both is belt-and-braces.
  const assertionHasGps = derived.latitude != null && derived.longitude != null;

  // Layer 1 — declared level: a non-precise level forbids GPS in either artifact.
  if (declared !== "precise" && (fileHasGps || assertionHasGps)) {
    const where = [
      fileHasGps ? "file bytes" : null,
      assertionHasGps ? "signed assertion" : null,
    ]
      .filter(Boolean)
      .join(" + ");
    throw new VerifyError(
      VerifyErrorCode.LOCATION_PRIVACY_VIOLATION,
      `a '${declared}' location upload carries GPS (${where}) — a non-precise ` +
        `upload must publish no coordinates`,
    );
  }

  // Layer 2 — bytes-vs-assertion spine (arg-independent backstop).
  if (fileHasGps && !assertionHasGps) {
    throw new VerifyError(
      VerifyErrorCode.LOCATION_PRIVACY_VIOLATION,
      "uploaded bytes carry GPS absent from the signed manifest — a non-precise " +
        "upload leaked coordinates into the public file",
    );
  }

  return { displayLeak: assertionHasGps && !fileHasGps };
}
