// Generative-AI provenance policy. Pure functions over a parsed manifest
// store — no I/O. Both the Cloud Run verifier (server) and the React Native
// client preflight gate consume these: the verifier throws
// VerifyError(AI_GENERATED); the client maps a hit to its AI_GENERATED card.
//
// Why a policy of its own, ahead of trust: the action allowlist admits
// `c2pa.created` on a capture and says nothing about what KIND of creation
// it was. A trusted issuer's manifest declaring that a model produced the
// content is chain-valid, structurally a fresh capture, and still not a
// photograph. RealReel shares captures only, so the declaration itself is
// disqualifying, whoever signed it — the check runs on the file's whole
// provenance claim, before any issuer or structural rule, and the verdict
// names the content rather than the signer.

import { getActiveManifest } from "../shapes/index.js";
import type { ManifestShape, ManifestStoreShape } from "../shapes/manifest.js";
import { extractActionEntries } from "./actions.js";

const IPTC_DIGITAL_SOURCE_TYPE = "http://cv.iptc.org/newscodes/digitalsourcetype/";

/**
 * IPTC digital source types that declare generative-AI provenance.
 * `trainedAlgorithmicMedia` is content a model produced outright (the
 * Conformance Program's synthetic video sample and an OpenAI image both sign
 * their `c2pa.created` with it); `compositeWithTrainedAlgorithmicMedia` is a
 * capture a model changed (Pixel Magic Editor signs its `c2pa.edited` with
 * it). Neighbouring terms stay out on purpose: `algorithmicMedia` is
 * procedural rendering with no model behind it, `compositeSynthetic` covers
 * any synthetic element (CGI included), and `computationalCapture` /
 * `algorithmicallyEnhanced` are camera pipelines. Calling those "AI" would
 * misdescribe the file.
 */
export const GENERATIVE_AI_SOURCE_TYPES: ReadonlySet<string> = new Set([
  `${IPTC_DIGITAL_SOURCE_TYPE}trainedAlgorithmicMedia`,
  `${IPTC_DIGITAL_SOURCE_TYPE}compositeWithTrainedAlgorithmicMedia`,
]);

/** Where in the store a generative-AI declaration was found. */
export interface GenerativeAiSource {
  /** Label of the manifest carrying the declaring action. */
  label: string;
  /** The declaring action's name (`c2pa.created`, `c2pa.edited`, …). */
  action: string;
  /** The declared digitalSourceType, verbatim. */
  digitalSourceType: string;
}

/** Bound on the ingredient walk. Real lineages are a few manifests deep; the
 *  cap only stops a pathological store, it never errors. */
const REACHABLE_MAX_DEPTH = 16;

/**
 * Find the first action whose `digitalSourceType` is one of
 * GENERATIVE_AI_SOURCE_TYPES on the active manifest or any manifest it
 * references through an ingredient. Null when none, and null when the store
 * has no resolvable active manifest (there is no provenance claim to read;
 * the caller's structural checks report that).
 *
 * Reachability, not the whole `manifests` map: the active manifest is the
 * file's provenance claim and its ingredients are what it attests to, so a
 * stray manifest nothing references cannot relabel a genuine capture. Every
 * ingredient relationship is followed, not just `parentOf`: a generated
 * asset's lineage runs through `inputTo` (prompt sources, model inputs) as
 * often as `parentOf`, and the Program's PNG sample buries the generation two
 * edits down. Breadth-first from the active manifest, cycle-guarded by label,
 * so the returned entry is deterministic for a given store. Action entries
 * come from extractActionEntries, so nested `related` sub-actions count and
 * both `c2pa.actions` and `c2pa.actions.v2` are read. The `https` spelling of
 * the vocabulary URI is accepted alongside the canonical `http`.
 */
export function findGenerativeAiSource(store: ManifestStoreShape): GenerativeAiSource | null {
  const activeLabel = store.active_manifest;
  const active = getActiveManifest(store);
  if (!active || typeof activeLabel !== "string") return null;

  const visited = new Set<string>([activeLabel]);
  let frontier: Array<{ label: string; manifest: ManifestShape }> = [
    { label: activeLabel, manifest: active },
  ];
  for (let depth = 0; depth <= REACHABLE_MAX_DEPTH && frontier.length > 0; depth++) {
    const next: Array<{ label: string; manifest: ManifestShape }> = [];
    for (const { label, manifest } of frontier) {
      for (const entry of extractActionEntries(manifest)) {
        const dst = entry.digitalSourceType;
        if (!dst) continue;
        if (!GENERATIVE_AI_SOURCE_TYPES.has(dst.replace(/^https:\/\//, "http://"))) continue;
        return { label, action: entry.action, digitalSourceType: dst };
      }
      for (const ingredient of manifest.ingredients ?? []) {
        const ref = ingredient?.active_manifest;
        if (typeof ref !== "string" || visited.has(ref)) continue;
        visited.add(ref);
        const target = store.manifests?.[ref];
        if (target) next.push({ label: ref, manifest: target });
      }
    }
    frontier = next;
  }
  return null;
}
