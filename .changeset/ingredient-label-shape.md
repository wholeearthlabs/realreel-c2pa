---
"@realreel/c2pa-trust-core": patch
---

`IngredientShape` gains the optional `label` c2pa-rs emits on every ingredient entry — the label of the `c2pa.ingredient.*` assertion it was read from, instance-suffixed past the first. Joined with the holding manifest's label it is the `ingredientAssertionURI` under which `validation_results.ingredientDeltas[]` files that ingredient's validation codes; the verifier uses it to find a wrapped capture's OCSP status.
