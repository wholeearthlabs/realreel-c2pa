// Per-content dedup identity — pure, crypto-free (the caller hashes the result;
// trust-core stays crypto-free for the RN client). The verifier turns this into
// media.content_hash, the key behind the per-profile "no duplicate uploads"
// index. Full rationale + threat model: docs/TRUST_ARCHITECTURE.md (app repo).
//
// Identity = the resolved Stage-1 CAPTURE manifest label (not the bytes) plus,
// for video, the signed trim/crop extent. Anchoring on the capture means the
// same capture re-uploaded with any transform collides, while two different
// video trims don't. The label is the anchor (not a byte digest) because
// c2pa-node doesn't surface a capture's hash binding for an ingredient manifest,
// and the label is invariant to offline-TSA-drain state. Trim matching is exact.

import type { ManifestShape } from "../shapes/manifest.js";
import { extractActionEntries } from "./actions.js";

/**
 * Actions whose parameters change WHICH portion of the capture is published,
 * making the upload a distinct piece of content. Everything else on the Stage-2
 * allowlist (resize/rotate/transcode/redact/opened) leaves the published extent
 * unchanged and is deliberately excluded.
 */
const EXTENT_ACTION_LABELS: ReadonlySet<string> = new Set([
  "c2pa.trimmed",
  "c2pa.cropped",
]);

/**
 * Deterministic JSON serialization: object keys sorted recursively, numbers
 * normalized, non-finite/undefined collapsed to "null". Independent of the
 * emitter's key order so the same trim always serializes identically.
 */
function canonicalJson(value: unknown): string {
  if (value === null || value === undefined) return "null";
  if (typeof value === "number") return Number.isFinite(value) ? String(value) : "null";
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "string") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (typeof value === "object") {
    const obj = value as Record<string, unknown>;
    return `{${Object.keys(obj)
      .sort()
      .map((k) => `${JSON.stringify(k)}:${canonicalJson(obj[k])}`)
      .join(",")}}`;
  }
  // function / symbol — not expressible in a manifest; treat as absent.
  return "null";
}

/**
 * Published-extent signature of an upload (Stage-2 / active) manifest: each
 * extent-defining action serialized `action:canonicalParams`, sorted and
 * ";"-joined. "" for a whole-capture upload (every photo today, any untrimmed
 * video). Shares extractActionEntries with the allowlist policy, so malformed
 * shapes are tolerated identically.
 */
export function extractContentExtent(active: ManifestShape): string {
  const parts: string[] = [];
  for (const { action, parameters } of extractActionEntries(active)) {
    if (!EXTENT_ACTION_LABELS.has(action)) continue;
    parts.push(`${action}:${canonicalJson(parameters)}`);
  }
  return parts.sort().join(";");
}

/**
 * Build the dedup identity string: `<capture label>[|<extent>]`.
 *
 * @param capture resolved Stage-1 capture manifest (caller has already walked
 *   past any interposed timestamp Update Manifests).
 * @param active  Stage-2 upload manifest carrying the signed trim/crop params.
 * @returns the identity, or null if the capture has no label (anomalous — a
 *   validated store always labels its manifests; the caller treats null as a
 *   hard error, never a silent dedup skip). The caller hashes this
 *   (sha256("rrc1:" + identity)); the scheme prefix lives caller-side.
 */
export function buildContentIdentity(
  capture: ManifestShape,
  active: ManifestShape,
): string | null {
  const label = capture.label;
  if (typeof label !== "string" || label.length === 0) return null;
  const extent = extractContentExtent(active);
  return extent ? `${label}|${extent}` : label;
}
