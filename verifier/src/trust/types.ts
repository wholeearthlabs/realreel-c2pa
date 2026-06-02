// Types for the trust-source layer.
//
// TrustSource: one entry in trust-sources.yaml after loading + reading the
// referenced PEM. The yaml-derived fields stay snake_case to match the
// public-facing format; runtime-derived fields (rootCertPem) are camelCase.
//
// The `issuerMatch` string used by identifyTrustSource() is NOT carried
// here — it lives on `@realreel/c2pa-trust-core` TRUSTED_ISSUERS, joined
// by `id`. This way the React Native client preflight gate and the server
// dispatcher read from the same authoritative list.

// Verification profile = role this trust anchor plays at ingestion.
//   "realreel"          — eligible to sign the ACTIVE (Stage 2) manifest.
//                         The only profile the verifier dispatches at
//                         ingestion (see verify.ts force-wrap gate).
//   "wrap_parent_only"  — trusted ONLY as a Stage 1 parent inside a
//                         RealReel-wrapped upload (today: Pixel). Its
//                         root sits in the c2pa-node trust bundle so
//                         parent-chain validation succeeds, but a raw
//                         single-stage upload chained to this root is
//                         rejected at the force-wrap gate.
export type VerificationProfile = "realreel" | "wrap_parent_only";

export interface TrustSourceConfig {
  id: string;
  name: string;
  description: string;
  root_cert: string;
  verification_profile: VerificationProfile;
}

export interface TrustSource extends TrustSourceConfig {
  /** PEM contents read from `root_cert` at startup. */
  rootCertPem: string;
}

/**
 * TSA (Time-Stamp Authority) root entry from trust-sources.yaml's top-level
 * `tsa_roots:` array. A TSA root is NOT a content issuer — it only validates
 * RFC 3161 timestamp tokens (sigTst2) embedded in COSE signatures, so it has
 * no verification_profile and no TRUSTED_ISSUERS
 * lockstep. Its PEM is concatenated into the SAME `trustAnchorsBundle`
 * c2pa-node consumes (c2pa-rs uses one trust pool for both signing-cert and
 * TSA validation).
 *
 * The bundled list is typically the full C2PA TSA Trust List
 * (https://github.com/c2pa-org/conformance-public/blob/main/trust-list/C2PA-TSA-TRUST-LIST.pem)
 * — wider than what we emit (DigiCert + SSL.com), but harmless since we still
 * only sign through our two providers, and it future-proofs against C2PA
 * adding more vetted TSAs.
 */
export interface TsaRootConfig {
  id: string;
  /** Operator-facing label only — never consumed by runtime code or emitted
   * on the wire; not validated by the loader. */
  name: string;
  /** Operator-facing description (rotation cadence, why it's bundled, what
   * upstream change triggers a re-vendor). Not validated. */
  description: string;
  /** Path (relative to trust-sources.yaml) to a PEM file containing one
   * or more concatenated TSA root certificates. */
  root_cert: string;
}

export interface TsaRoot extends TsaRootConfig {
  rootCertPem: string;
}

export interface TrustConfig {
  /** All sources from trust-sources.yaml whose root_cert file exists. */
  sources: TrustSource[];

  /** TSA roots from trust-sources.yaml's `tsa_roots:` (post-load). */
  tsaRoots: TsaRoot[];

  /** Concatenated PEM bundle to pass to c2pa-node's settings.trust.trust_anchors.
   *  Includes BOTH signer roots (from `sources`) AND TSA roots (from `tsaRoots`)
   *  — c2pa-rs uses one pool for both signing-cert and TSA validation. */
  trustAnchorsBundle: string;

  /** Set of source ids whose PEM loaded successfully. Read by
   * identifyTrustSource() on every /verify request — pre-computed so it isn't
   * rebuilt on the hot path. Immutable after the loader returns. */
  loadedIds: ReadonlySet<string>;
}
