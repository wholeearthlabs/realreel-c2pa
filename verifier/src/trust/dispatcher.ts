// Routes a c2pa-node-verified manifest to the right verification profile
// based on the signing leaf's organization.
//
// By the time this runs, c2pa-node has validated the chain, but against ONE
// pool: every camera root plus every TSA root, including public CAs that
// issue claim-signing certs to any organization they vet. A valid chain
// therefore says only "some pooled CA issued this". What scopes a cert to a
// source is this match: exact equality of `signature_info.issuer` (c2pa-rs:
// the leaf's subject O) with the entry's `issuerMatch`, AND, when the entry
// pins one, of `common_name` with its `commonNameMatch`. Never substring: a
// pooled CA would issue a real cert to an organization whose name merely
// contains a trusted one. The criteria are the client preflight gate's
// (findTrustedIssuer in @realreel/c2pa-trust-core), so both agree.

import { TRUSTED_ISSUERS, matchesCommonName } from "@realreel/c2pa-trust-core";
import type {
  RevocationConfig,
  TrustConfig,
  VerificationProfile,
} from "./types.js";

/**
 * Resolve a signature's issuer + common_name to a trust-source id, or
 * null if no trusted issuer's `issuerMatch` equals
 * `signatureIssuer` (AND, when defined, its `commonNameMatch` admits
 * `signatureCommonName`) AND the corresponding source is loaded (i.e.,
 * its `root_cert` file exists on disk and produced a non-skipped
 * TrustSource at startup).
 *
 * Iterates TRUSTED_ISSUERS in declaration order. The "loaded" filter against
 * `trustConfig.loadedIds` is a regression guard, not a security boundary: a
 * source whose PEM didn't load also isn't in `trustAnchorsBundle`, so
 * c2pa-node rejects manifests signed by it at chain validation before this
 * runs. The filter only bites if a cert chains to a different loaded root
 * yet carries another source's organization — keeping it makes such deploy
 * drift surface as a clean UNTRUSTED_ISSUER rather than a misrouted profile.
 *
 * @param signatureIssuer  The leaf cert's subject O as surfaced by
 *   c2pa-node (signature_info.issuer).
 * @param signatureCommonName  The leaf cert's subject CN as surfaced by
 *   c2pa-node (signature_info.common_name). Consulted only by entries
 *   whose `commonNameMatch` is set (today: Pixel and ProofMode);
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
    if (signatureIssuer !== entry.issuerMatch) continue;
    // Tightening pin: the same check the client gate's findTrustedIssuer
    // applies, so both route on identical criteria.
    if (!matchesCommonName(entry, signatureCommonName)) continue;
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
  revocation?: RevocationConfig;
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
      revocation: source.revocation,
    };
  };
}
