// Sanitize a c2pa-node ManifestStore for persistence in media.c2pa_manifest.
//
// The verifier validates the manifest once at ingest and the stored asset is
// immutable thereafter, so anything whose only purpose is re-verification is
// dropped:
//
//   1. Signature bytes (the COSE_Sign1 signature inside each manifest's
//      claim). Hundreds of bytes per manifest; only useful to a re-verifier,
//      and the verifier already validated them.
//   2. Embedded cert chain (signer's leaf + intermediates). A few hundred
//      bytes to a few KB. Already embedded in the asset file in Storage.
//   3. Re-verification-only assertions (see isReVerificationOnly): the
//      c2pa.hash.* hard-bindings (which bind the claim to the asset bytes),
//      the RFC 3161 timestamp token (its stamp time survives as
//      signature_info.time), and the per-upload attestation envelopes
//      (consumed at verify). None carries provenance a viewer would show.
//
// Keeps the human-readable provenance a manifest viewer renders:
//   - claim_generator, title, format
//   - signature_info (issuer DN, leaf common_name, signing alg, timestamp
//     time + the TSA provider name — provenance only, NOT the cert bytes
//     behind them)
//   - the remaining assertions (label + data): the c2pa.actions log,
//     org.realreel.capture / .upload, and the signed stds.exif
//   - validation_status (codes for display)
//   - ingredients (title, format, relationship, parent-manifest pointer)
//     so a viewer can render and walk the provenance chain
//
// Adds:
//   - trust_source (string id from trust-sources.yaml — populated by
//     the orchestrator, not by this function)
//   - validation_state (top-level summary: 'trusted' if validation_status
//     is empty after c2pa-node returns, otherwise 'invalid')
//
// Size: ~4 KB for a typical RealReel 2-stage row (the signed EXIF + actions
// log + capture/upload assertions dominate). Pinned against real fixtures in
// __tests__/verify-realreel*.test.ts; the structural guard in
// __tests__/sanitize.test.ts catches a kept-shape regression.

import {
  APP_ATTEST_LABEL,
  PLAY_INTEGRITY_LABEL,
  TIMESTAMP_ASSERTION_LABEL,
} from "@realreel/c2pa-trust-core";

export interface SanitizedAssertion {
  label: string;
  data: unknown;
}

export interface SanitizedIngredient {
  title: string | null;
  format: string | null;
  /** C2PA relationship of this ingredient to its manifest, e.g. "parentOf". */
  relationship: string | null;
  /** Label of this ingredient's own manifest in the store, if it carries
   * one (the parent Stage-1). null otherwise. */
  active_manifest: string | null;
}

export interface SanitizedManifest {
  label: string;
  claim_generator: string | null;
  title: string | null;
  format: string | null;
  signature_info: {
    issuer: string | null;
    /** Leaf cert subject CN, e.g. "Pixel Camera" — the human-readable
     * signer name behind the issuer DN. */
    common_name: string | null;
    /** Signing algorithm as surfaced by c2pa-rs, e.g. "Es256". */
    alg: string | null;
    /** Signing instant. When a sigTst2 timestamp is present, c2pa-rs
     * populates this from the TSA token's genTime — i.e. the time the
     * signature was timestamped. */
    time: string | null;
    /** Name of the RFC-3161 Time-Stamping Authority that stamped this
     * manifest's signature, lifted from c2pa-rs's validation_results by
     * extractTsaByLabel. null when the manifest carries no sigTst2. Display
     * provenance only — non-null is NOT a trust assertion (an untrusted stamp
     * still names its TSA; trust is decided upstream of sanitize). */
    timestamp_authority: string | null;
  };
  assertions: SanitizedAssertion[];
  ingredients: SanitizedIngredient[];
  /** Convenience pointer: the first parent ingredient's manifest label
   * (Stage-2 wrapping a parent Stage-1), equal to that ingredient's
   * active_manifest. null for unparented manifests. */
  parent_label: string | null;
}

export interface SanitizedManifestStore {
  active_manifest: SanitizedManifest | null;
  manifests: Record<string, SanitizedManifest>;
  validation_status: Array<{
    code: string;
    explanation: string | null;
    url: string | null;
  }>;
  /** Top-level summary: 'trusted' if c2pa-node returned no validation
   * issues at the time sanitization runs, otherwise 'invalid'. Derived
   * inline from validation_status — see sanitizeManifestStore.
   *
   * In practice always 'trusted': the realreel profile (the only ingestion
   * profile) calls classifyStrictValidationStatus() before we get here,
   * which throws on any non-empty status. The 'invalid' value is retained
   * for a future profile that tolerates warning-level validation results. */
  validation_state: "trusted" | "invalid";
  /** Source id from trust-sources.yaml (e.g. 'realreel', 'pixel'). Populated
   * by the orchestrator after identifyTrustSource() resolves. */
  trust_source: string;
}

/**
 * Walk a c2pa-node ResolvedManifestStore and produce the sanitized JSON
 * shape we persist. The input type is loose (`unknown`); this function does
 * best-effort extraction and leaves null where fields are absent.
 *
 * @param store c2pa-node's ResolvedManifestStore (from Reader.read()).
 * @param trustSource Source id from identifyTrustSource().
 */
export function sanitizeManifestStore(
  store: unknown,
  trustSource: string,
): SanitizedManifestStore {
  // Cast through the shared ManifestStoreShape (see c2pa-shape.ts).
  // sanitize is the only consumer of manifest entries as unknown — it
  // does best-effort field plucking with null fallbacks, so loose
  // typing inside the per-manifest walk is intentional.
  const s = store as {
    active_manifest?: string;
    manifests?: Record<string, unknown>;
    validation_status?: Array<{
      code: string;
      explanation?: string | null;
      url?: string | null;
    }>;
    validation_results?: ValidationResults;
  };

  // Resolve each manifest's TSA provider name BEFORE the per-manifest walk —
  // the name lives in store-level validation_results, not on the manifest.
  const tsaByLabel = extractTsaByLabel(s);

  const manifests: Record<string, SanitizedManifest> = {};
  if (s.manifests && typeof s.manifests === "object") {
    for (const [label, manifest] of Object.entries(s.manifests)) {
      manifests[label] = sanitizeManifest(label, manifest, tsaByLabel[label] ?? null);
    }
  }

  const activeManifestLabel = typeof s.active_manifest === "string"
    ? s.active_manifest
    : null;
  const active = activeManifestLabel ? (manifests[activeManifestLabel] ?? null) : null;

  const validation_status = (s.validation_status ?? []).map((v) => ({
    code: v.code,
    explanation: v.explanation ?? null,
    url: v.url ?? null,
  }));

  return {
    active_manifest: active,
    manifests,
    validation_status,
    validation_state: validation_status.length === 0 ? "trusted" : "invalid",
    trust_source: trustSource,
  };
}

/** A single c2pa-rs validation entry: a {code, url, explanation} triple. */
interface ValidationEntry {
  code?: string;
  url?: string | null;
  explanation?: string | null;
}
/** The three c2pa-rs validation buckets attached to a manifest's results. */
interface ValidationBuckets {
  success?: ValidationEntry[];
  informational?: ValidationEntry[];
  failure?: ValidationEntry[];
}
/** c2pa-rs's per-store validation_results: the active manifest's buckets plus
 * one delta per ingredient (where a parent manifest's entries surface). */
interface ValidationResults {
  activeManifest?: ValidationBuckets;
  ingredientDeltas?: Array<{ validationDeltas?: ValidationBuckets }>;
}

// A timestamped signature's JUMBF URI → the owning manifest label, e.g.
// "self#jumbf=/c2pa/urn:c2pa:abc…/c2pa.signature" → "urn:c2pa:abc…".
const TSA_LABEL_FROM_URL = /\/c2pa\/([^/]+)\/c2pa\.signature/;

/**
 * Build a manifest-label → TSA-provider-name map from c2pa-rs's
 * validation_results.
 *
 * The provider name is not a structured field in the c2pa-node output: it
 * appears only in the human-readable explanation of the `timeStamp.*` entries
 * (e.g. "timestamp message digest matched: DigiCert SHA256 …"), so we take the
 * substring after the first ": " and key it by the manifest label parsed from
 * the entry's `url`. A parent (Stage-1) manifest's entries surface under
 * `ingredientDeltas[]` and nested in its ingredient's results, while the active
 * manifest's are under `activeManifest` — so all three are scanned. The names
 * agree across the validated/trusted/untrusted codes, so the first match wins.
 */
function extractTsaByLabel(s: {
  manifests?: Record<string, unknown>;
  validation_results?: ValidationResults;
}): Record<string, string> {
  const byLabel: Record<string, string> = {};

  const consider = (entries: ValidationEntry[] | undefined): void => {
    for (const e of entries ?? []) {
      if (typeof e?.code !== "string" || !e.code.startsWith("timeStamp.")) continue;
      const match = (typeof e.url === "string" ? e.url : "").match(TSA_LABEL_FROM_URL);
      if (!match) continue;
      const label = match[1]!;
      if (byLabel[label]) continue;
      const explanation = typeof e.explanation === "string" ? e.explanation : "";
      const sep = explanation.indexOf(": ");
      // Cap the lifted name: it derives from a cert subject CN (attacker-
      // influenced for an untrusted stamp), and this module's contract is to
      // bound what we persist. A real TSA name is ~50 chars; 200 is slack.
      const name = sep >= 0 ? explanation.slice(sep + 2, sep + 202).trim() : "";
      if (name) byLabel[label] = name;
    }
  };
  // success carries validated/trusted stamps and informational carries an
  // untrusted-but-present stamp — both name the TSA. A timeStamp.* entry in the
  // failure bucket means the stamp itself didn't validate, so its provider is
  // deliberately NOT surfaced as a timestamp.
  const scan = (b: ValidationBuckets | undefined): void => {
    if (!b) return;
    consider(b.success);
    consider(b.informational);
  };

  const vr = s.validation_results;
  scan(vr?.activeManifest);
  for (const delta of vr?.ingredientDeltas ?? []) scan(delta?.validationDeltas);
  for (const manifest of Object.values(s.manifests ?? {})) {
    const ingredients = (
      manifest as {
        ingredients?: Array<{ validation_results?: { activeManifest?: ValidationBuckets } }>;
      }
    ).ingredients;
    for (const ing of ingredients ?? []) scan(ing?.validation_results?.activeManifest);
  }

  return byLabel;
}

// Assertions kept only for re-verification (or consumed at ingest) carry no
// provenance a manifest viewer would render, so they're dropped from the
// persisted shape — same rationale as the signature-bytes / cert-chain drop.
// This is a denylist, not an allowlist: an unknown vendor's provenance
// assertion is kept by default rather than silently discarded.
function isReVerificationOnly(label: string): boolean {
  // c2pa.hash.* hard-bindings (data, data.part, boxes, bmff, multi-asset, …)
  // bind the claim to the asset bytes; only a re-verifier needs them.
  if (label.startsWith("c2pa.hash.")) return true;
  // RFC 3161 timestamp token (the ~8 KB offline-drain blob). The stamp time a
  // viewer shows survives as signature_info.time, and the TSA provider NAME is
  // lifted out separately into signature_info.timestamp_authority (a few tens
  // of bytes, from c2pa-rs's validation_results — see extractTsaByLabel). So
  // the ~8 KB token itself carries nothing a viewer needs and is dropped.
  if (label === TIMESTAMP_ASSERTION_LABEL) return true;
  // Per-upload device-attestation envelopes; their nonce is burned at verify.
  if (label === PLAY_INTEGRITY_LABEL) return true;
  if (label === APP_ATTEST_LABEL) return true;
  return false;
}

function sanitizeManifest(
  label: string,
  manifest: unknown,
  timestampAuthority: string | null,
): SanitizedManifest {
  const m = manifest as {
    label?: string;
    claim_generator?: string;
    title?: string;
    format?: string;
    signature_info?: {
      issuer?: string;
      common_name?: string;
      alg?: string;
      time?: string;
      timeObject?: Date;
    };
    assertions?: Array<{ label?: string; data?: unknown }>;
    ingredients?: Array<{
      title?: string;
      format?: string;
      relationship?: string;
      active_manifest?: string;
    }>;
  };

  const assertions: SanitizedAssertion[] = (m.assertions ?? [])
    .filter((a): a is { label: string; data: unknown } => typeof a?.label === "string")
    .filter((a) => !isReVerificationOnly(a.label))
    .map((a) => ({ label: a.label, data: a.data ?? null }));

  const ingredients: SanitizedIngredient[] = (m.ingredients ?? []).map((i) => ({
    title: i?.title ?? null,
    format: i?.format ?? null,
    relationship: i?.relationship ?? null,
    active_manifest: i?.active_manifest ?? null,
  }));

  // Parent ingredient = the first ingredient that points at its own
  // manifest (Stage-1 wrapped by Stage-2). The C2PA spec allows multiple
  // ingredients but for RealReel the canonical case is exactly one parent.
  const parent_label = ingredients
    .map((i) => i.active_manifest)
    .find((l): l is string => typeof l === "string") ?? null;

  // Time: prefer ISO string from `time`; fall back to timeObject.toISOString().
  let time: string | null = null;
  if (typeof m.signature_info?.time === "string") {
    time = m.signature_info.time;
  } else if (m.signature_info?.timeObject instanceof Date) {
    time = m.signature_info.timeObject.toISOString();
  }

  return {
    label: m.label ?? label,
    claim_generator: m.claim_generator ?? null,
    title: m.title ?? null,
    format: m.format ?? null,
    signature_info: {
      issuer: m.signature_info?.issuer ?? null,
      common_name: m.signature_info?.common_name ?? null,
      alg: m.signature_info?.alg ?? null,
      time,
      timestamp_authority: timestampAuthority,
    },
    assertions,
    ingredients,
    parent_label,
  };
}

