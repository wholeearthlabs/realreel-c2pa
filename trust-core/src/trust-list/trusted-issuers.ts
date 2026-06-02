// Curated allowlist of trusted C2PA content sources. The metadata here
// is the audit-friendly subset of trust-list state that both the React
// Native client preflight gate and the Cloud Run verifier consume:
//
//   - The client uses `issuerMatch` to decide whether a manifest in the
//     user's camera roll came from a trusted camera/PEM. No PEMs, no
//     chain validation — just an issuer-string substring check.
//
//   - The server uses the same `issuerMatch` for dispatch (routing a
//     manifest to its verification profile). Separately, the server
//     also validates the cryptographic chain against the actual root
//     PEM — those PEMs live in verifier/trust-sources/<id>/root.pem
//     today. A lockstep test (verifier/__tests__/trust-list-lockstep.test.ts)
//     parses each PEM and asserts its subject CN matches the
//     `rootCommonName` field here, so the metadata can't silently drift
//     from the actual cryptographic trust anchor.
//
// Adding a new trusted source:
//   1. Source the camera vendor's published C2PA root PEM (verify against
//      a real fixture before trusting).
//   2. Add an entry below with the empirically-pinned `issuerMatch`
//      string and the root PEM's subject CN as `rootCommonName`.
//   3. Commit the PEM at verifier/trust-sources/<id>/root.pem.
//   4. The lockstep test fails fast if the strings don't match.
//   5. Add a verifier profile mapping for the new id (server-side, separate
//      from this trust-list addition).

import type { ManifestShape } from "../shapes/manifest.js";

export interface TrustedIssuer {
  /** Stable slug used for telemetry tags, the server's trust source id,
   * and client UI grouping. Must be unique across TRUSTED_ISSUERS — a
   * unit test enforces this. */
  id: string;

  /** Human-readable label for UI surfaces ("Capture taken with: RealReel"
   * or "Pixel"). Suitable for direct display to end users. */
  displayName: string;

  /** Substring matched against `signature_info.issuer` (the string
   * c2pa-rs surfaces from the signing leaf cert's issuer DN). Both
   * client and server use this to identify which trusted source signed
   * a manifest. The match is INTENTIONALLY a substring rather than an
   * exact match because c2pa-rs's surfacing of the issuer DN varies
   * across cert chain shapes; pinning the substring empirically against
   * real fixtures is the only way to track its output.
   *
   * Collision-avoidance: when adding an issuer, ensure its
   * `issuerMatch` is NOT a substring of any other entry's match (and
   * vice versa). The trust-list uniqueness test enforces this. */
  issuerMatch: string;

  /** Optional pin against `signature_info.common_name` (leaf cert
   * subject CN). When set, findTrustedIssuer requires BOTH issuerMatch
   * AND exact common_name equality before resolving to this entry.
   *
   * Used when the issuer field alone is too coarse to uniquely identify
   * a vendor's specific C2PA program: e.g. Pixel signs with
   * `issuer = "Google LLC"`, which would also match a future Google
   * Workspace / Drive C2PA program. Pinning `common_name = "Pixel
   * Camera"` keeps the match scoped to Pixel until Google ships a
   * second program with the same common_name (in which case we revisit
   * the discriminator).
   *
   * Undefined entries (e.g. RealReel) match on issuerMatch alone. */
  commonNameMatch?: string;

  /** Subject CN of the root PEM that anchors this issuer's cert chain.
   * Documented here so the metadata stays auditable from the shared
   * package alone, without consumers needing to parse PEM bytes.
   * Drift between this string and the actual PEM is caught by a
   * lockstep test on the server side that reads each PEM and asserts
   * its subject CN matches. */
  rootCommonName: string;
}

/**
 * The curated list. Order is significant for telemetry stability but not
 * for matching correctness (issuerMatch substrings are unique).
 *
 * RealReel (our own captures) + Google Pixel (Pixel 8 and later, stock
 * Camera app with Content Credentials). Add Sony, Leica, Nikon, etc. as
 * their published roots are verified against real fixtures.
 */
export const TRUSTED_ISSUERS: ReadonlyArray<TrustedIssuer> = [
  {
    id: "realreel",
    displayName: "RealReel",
    // Empirically pinned against verifier/__tests__/fixtures/realreel-uploaded.jpg
    // (real iPhone capture). c2pa-rs surfaces the short string "RealReel"
    // for certs issued by our CA — exact derivation isn't documented but
    // the leaf's issuer DN is `CN=RealReel Issuing CA`.
    issuerMatch: "RealReel",
    rootCommonName: "RealReel Root CA",
  },
  {
    id: "pixel",
    displayName: "Pixel",
    // Empirically pinned against verifier/__tests__/fixtures/pixel-og.jpg
    // and pixel-uploaded.jpg (both surface signature_info.common_name =
    // "Pixel Camera"). issuerMatch "Google LLC" is intentionally narrowed
    // by commonNameMatch so a future Google-LLC-signed but non-Pixel
    // C2PA program (Workspace, Drive, etc.) cannot route through this
    // entry. If/when Google ships another program legitimately under
    // common_name = "Pixel Camera", we revisit the discriminator —
    // unlikely, since the CN matches the user-facing app name.
    issuerMatch: "Google LLC",
    commonNameMatch: "Pixel Camera",
    rootCommonName: "Google C2PA Root CA G3",
  },
];

/**
 * Look up a trusted issuer by a manifest's `signature_info.issuer`
 * string. Returns the first entry whose `issuerMatch` is a substring
 * of the issuer field, or null if none match.
 *
 * Both the client preflight gate (decides whether to accept the upload)
 * and the server's dispatcher (decides which verification profile to
 * run) use this. They MUST agree on the match — sharing this function
 * is what guarantees they do.
 *
 * Returns null when:
 *   - signature_info is missing entirely (unsigned manifest).
 *   - issuer field is missing or non-string.
 *   - No entry's substring matches.
 *
 * Client maps null → ClientGateReason.ISSUER_NOT_TRUSTED. Server maps null →
 * UNTRUSTED_ISSUER (an untrusted issuer wouldn't have chained to a trust
 * anchor anyway, so chain validation already rejects it).
 */
export function findTrustedIssuer(manifest: ManifestShape): TrustedIssuer | null {
  const issuer = manifest.signature_info?.issuer;
  if (typeof issuer !== "string" || issuer.length === 0) return null;
  const commonName = manifest.signature_info?.common_name;
  return (
    TRUSTED_ISSUERS.find((entry) => {
      if (!issuer.includes(entry.issuerMatch)) return false;
      // If this entry pins common_name, require exact match. Entries
      // without a commonNameMatch (e.g. RealReel) accept any common_name
      // value (including missing) and route on issuerMatch alone — see
      // the field's JSDoc for the rationale.
      if (entry.commonNameMatch === undefined) return true;
      return commonName === entry.commonNameMatch;
    }) ?? null
  );
}
