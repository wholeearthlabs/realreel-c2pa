// Generative-AI provenance gate. An orchestrator-level check, beside
// cert-validity and location-privacy, that verify.ts runs on the parsed
// store ahead of issuer resolution — so a trusted camera's model output and
// a foreign generator's both read AI_GENERATED rather than a trust or
// structure code. The pure policy is findGenerativeAiSource, exported by
// @realreel/c2pa-trust-core (trust-core/src/policies/generative-ai.ts); this
// wrapper turns a hit into the thrown VerifyError.

import { findGenerativeAiSource } from "@realreel/c2pa-trust-core";
import { VerifyError, VerifyErrorCode } from "./errors.js";
import type { ManifestStoreShape } from "./c2pa-shape.js";

/**
 * Reject a store whose active manifest, or any manifest it references
 * through an ingredient, declares generative-AI provenance. Throws
 * AI_GENERATED naming the manifest, action, and source type.
 */
export function enforceNoGenerativeAi(store: ManifestStoreShape): void {
  const hit = findGenerativeAiSource(store);
  if (hit) {
    throw new VerifyError(
      VerifyErrorCode.AI_GENERATED,
      `manifest '${hit.label}' declares ${hit.action} with digitalSourceType '${hit.digitalSourceType}'`,
    );
  }
}
