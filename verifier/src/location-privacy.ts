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
// (2) Bytes-vs-assertion spine (arg-independent). The file bytes and the signed
//     assertion come from two independent write-paths, and the bytes must never
//     carry GPS the assertion lacks: that is a non-precise upload whose strip
//     failed, leaking coordinates into the durable PUBLIC file. Hard reject
//     (fail closed), even if the declared field is wrong, forged, or its
//     plumbing regresses — the bytes are hash-bound, so we can't strip-and-keep
//     without breaking the signature.
//
//     The reverse, an assertion with GPS the bytes lack, passes: on a precise
//     upload it publishes only what the user chose (coordinates taken from the
//     capture's signed metadata rather than its bytes, or an EXIF round-trip
//     that dropped), and on a non-precise one layer 1 has already rejected it.
//
// Layer (1) also closes the spine's blind spot once the level is known: a
// correlated double-regression (both paths leak, reading as a consistent
// "precise").

import { VerifyError, VerifyErrorCode } from "./errors.js";
import type { DerivedMetadata } from "./derive-metadata.js";
import type { LocationLevel } from "@realreel/c2pa-trust-core";

/**
 * Throws VerifyError(LOCATION_PRIVACY_VIOLATION) on a declared-level violation
 * (a non-precise upload carrying GPS in bytes OR assertion) or a file leak
 * (bytes carrying GPS the assertion lacks).
 *
 * Pure over (DerivedMetadata, declared) — no I/O, fully unit-testable.
 */
export function enforceLocationPrivacy(
  derived: DerivedMetadata,
  declared: LocationLevel,
): void {
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
}
