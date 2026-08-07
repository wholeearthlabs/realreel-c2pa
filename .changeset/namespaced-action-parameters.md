---
"@realreel/photo-attest": minor
---

Entity-namespace the `Stage2Action` parameter keys (`width` → `org.realreel.width`, likewise `height`, `quality`, `format`, `angle`, `x`, `y`, `start`, `end`). C2PA 2.x §18.15.4.7 requires custom action parameter keys to carry a dot-separated entity namespace, and the conformance checker rejects bare keys (`validation:no_unrecognized_custom_action_parameters`). `c2pa.redacted`'s `assertionLabel` is unchanged — it is a signing-time instruction that native rewrites to the spec's pre-defined `redacted` key, never manifest content. Type-only change; both platforms pass parameters through verbatim.
