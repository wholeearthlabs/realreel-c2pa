---
"@realreel/c2pa-trust-core": minor
"@realreel/verifier": minor
---

Refuse generative-AI provenance, whoever signed it. trust-core adds `findGenerativeAiSource` / `GENERATIVE_AI_SOURCE_TYPES` (`policies/generative-ai`) and the `AI_GENERATED` verify-error code; the verifier runs the scan over the active manifest and every manifest it references (nested `related` sub-actions included) ahead of issuer resolution, so a trusted camera's AI output and a foreign generator's both reject as `AI_GENERATED` rather than a trust or structure code. The IPTC terms that count are `trainedAlgorithmicMedia` and `compositeWithTrainedAlgorithmicMedia`; camera pipelines (`computationalCapture`, `algorithmicallyEnhanced`) do not.
