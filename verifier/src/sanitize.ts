// Sanitize a c2pa-node ManifestStore for persistence in media.c2pa_manifest.
//
// Drops two big-and-redundant categories of data:
//
//   1. Signature bytes (the COSE_Sign1 signature inside each manifest's
//      claim). Hundreds of bytes per manifest; only useful to a
//      re-verifier, and the verifier already validated the bytes.
//   2. Embedded cert chain (signer's leaf + intermediates). Anywhere from
//      a few hundred bytes to a few KB. Already embedded in the asset
//      file in Storage; can be re-fetched if needed for display.
//
// Keeps:
//   - claim_generator, title, format
//   - signature_info (issuer DN string, timestamp Date — NOT the cert
//     bytes that produced the issuer)
//   - assertions (label + data — small, JSON-safe)
//   - validation_status (codes for display)
//   - parent ingredient pointer (so the UI can walk the chain)
//
// Adds:
//   - trust_source (string id from trust-sources.yaml — populated by
//     the orchestrator, not by this function)
//   - validation_state (top-level summary: 'trusted' if validation_status
//     is empty after c2pa-node returns, otherwise 'invalid')
//
// Target: ~1-2 KB per row for typical RealReel 2-stage manifests. The <2 KB
// ceiling is enforced by __tests__/sanitize.test.ts — if it creeps up,
// revisit which fields we keep.

export interface SanitizedAssertion {
  label: string;
  data: unknown;
}

export interface SanitizedManifest {
  label: string;
  claim_generator: string | null;
  title: string | null;
  format: string | null;
  signature_info: {
    issuer: string | null;
    time: string | null;
  };
  assertions: SanitizedAssertion[];
  /** Label of the parent ingredient's manifest, if this manifest has one
   * (Stage-2 wrapping a parent Stage-1). null for unparented manifests. */
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
  };

  const manifests: Record<string, SanitizedManifest> = {};
  if (s.manifests && typeof s.manifests === "object") {
    for (const [label, manifest] of Object.entries(s.manifests)) {
      manifests[label] = sanitizeManifest(label, manifest);
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

function sanitizeManifest(label: string, manifest: unknown): SanitizedManifest {
  const m = manifest as {
    label?: string;
    claim_generator?: string;
    title?: string;
    format?: string;
    signature_info?: {
      issuer?: string;
      time?: string;
      timeObject?: Date;
    };
    assertions?: Array<{ label?: string; data?: unknown }>;
    ingredients?: Array<{ active_manifest?: string }>;
  };

  const assertions: SanitizedAssertion[] = (m.assertions ?? [])
    .filter((a): a is { label: string; data: unknown } => typeof a?.label === "string")
    .map((a) => ({ label: a.label, data: a.data ?? null }));

  // Parent ingredient = the first ingredient that has its own
  // active_manifest pointer (Stage-1 wrapped by Stage-2). C2PA spec
  // allows multiple ingredients but for RealReel the canonical case is
  // exactly one parent.
  const parent_label = (m.ingredients ?? [])
    .map((i) => i?.active_manifest)
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
      time,
    },
    assertions,
    parent_label,
  };
}

