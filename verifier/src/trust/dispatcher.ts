// Routes a c2pa-node-verified manifest to the right verification profile
// based on the leaf cert's issuer DN.
//
// IMPORTANT — this is routing, NOT trust:
//
//   The trust gate is c2pa-node's chain validation against
//   trustConfig.trustAnchorsBundle (verify_trust_list: false +
//   trust_anchors: bundle). By the time identifyTrustSource() runs, the
//   manifest's cert chain has already been validated against a known
//   root from our bundle. Substring matching here is safe because it
//   operates only on already-trusted certs — an attacker can forge a
//   `CN=RealReel Issuing CA` string in their own cert, but unless that
//   cert chains to a root in our bundle, c2pa-node rejects it before we
//   ever see signature_info.issuer.
//
// Matching strategy: substring `includes()` on the issuer DN, AND (when the
// matched entry pins a `commonNameMatch`) exact equality on the leaf cert's
// `signature_info.common_name`. Real-world issuer DNs carry extra fields (O,
// C, OU), so substring is the right shape. `commonNameMatch` narrows a coarse
// issuer string (e.g. "Google LLC" matches any future Google C2PA program;
// the Pixel entry pins common_name="Pixel Camera"). The `issuerMatch` /
// `commonNameMatch` strings on @realreel/c2pa-trust-core TRUSTED_ISSUERS are
// shared with the React Native client preflight gate (findTrustedIssuer),
// guaranteeing both validators agree on what counts as a trusted issuer.

import { TRUSTED_ISSUERS } from "@realreel/c2pa-trust-core";
import type { TrustConfig, VerificationProfile } from "./types.js";

/**
 * Resolve a signature's issuer + common_name to a trust-source id, or
 * null if no trusted issuer's `issuerMatch` is a substring of
 * `signatureIssuer` (AND, when defined, its `commonNameMatch` equals
 * `signatureCommonName`) AND the corresponding source is loaded (i.e.,
 * its `root_cert` file exists on disk and produced a non-skipped
 * TrustSource at startup).
 *
 * Iterates TRUSTED_ISSUERS in declaration order. The "loaded" filter against
 * `trustConfig.loadedIds` is a regression guard, not a security boundary: a
 * source whose PEM didn't load also isn't in `trustAnchorsBundle`, so
 * c2pa-node rejects manifests signed by it at chain validation before this
 * runs. The filter only bites if an attacker's cert chains to a different
 * loaded root yet carries another source's issuerMatch substring in its DN —
 * keeping it makes such deploy drift surface as a clean UNTRUSTED_ISSUER
 * rather than a misrouted profile.
 *
 * @param signatureIssuer  The leaf cert's issuer DN as surfaced by
 *   c2pa-node (signature_info.issuer). Already-trusted at the
 *   chain-validation level — this is purely for profile dispatch.
 * @param signatureCommonName  The leaf cert's subject CN as surfaced by
 *   c2pa-node (signature_info.common_name). Consulted only by entries
 *   whose `commonNameMatch` is set (today: Pixel pins "Pixel Camera");
 *   ignored by entries without a pin. Pass null / undefined when
 *   absent.
 */
export function identifyTrustSource(
  signatureIssuer: string,
  signatureCommonName: string | null | undefined,
  trustConfig: TrustConfig,
): string | null {
  if (signatureIssuer.length === 0) return null;
  for (const entry of TRUSTED_ISSUERS) {
    if (!trustConfig.loadedIds.has(entry.id)) continue;
    if (!signatureIssuer.includes(entry.issuerMatch)) continue;
    // Tightening pin: when an entry specifies commonNameMatch, require
    // exact equality with the leaf's surfaced common_name. Mirrors
    // findTrustedIssuer in @realreel/c2pa-trust-core so the client gate
    // and the server-side dispatcher route on identical criteria.
    if (entry.commonNameMatch !== undefined && signatureCommonName !== entry.commonNameMatch) {
      continue;
    }
    return entry.id;
  }
  return null;
}

/** A trust source resolved for one specific manifest's signature identity:
 * the trust-sources.yaml id plus the role that source is allowed to play. */
export interface ResolvedTrustSource {
  id: string;
  name: string;
  profile: VerificationProfile;
}

/** Signature-identity → trust-source resolver. verify.ts builds one per
 * request and injects it into verifyRealReel to resolve the PARENT
 * capture's source — what makes `wrap_parent_only` an enforced role.
 * Injected so profiles/ stays decoupled from the trust-config loader. */
export type TrustSourceResolver = (
  signatureIssuer: string,
  signatureCommonName: string | null | undefined,
) => ResolvedTrustSource | null;

/**
 * Build a TrustSourceResolver over a loaded TrustConfig: identifyTrustSource
 * joined to the source's verification_profile. Null when the identity
 * matches no configured source (callers treat as UNTRUSTED_ISSUER).
 */
export function makeTrustSourceResolver(
  trustConfig: TrustConfig,
): TrustSourceResolver {
  return (signatureIssuer, signatureCommonName) => {
    const id = identifyTrustSource(
      signatureIssuer,
      signatureCommonName,
      trustConfig,
    );
    if (!id) return null;
    const source = trustConfig.sources.find((s) => s.id === id);
    if (!source) return null;
    return {
      id: source.id,
      name: source.name,
      profile: source.verification_profile,
    };
  };
}
