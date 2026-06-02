// Re-export shim. The manifest shape definitions live in
// @realreel/c2pa-trust-core so this verifier and the React Native client
// preflight share one source of truth; this keeps existing imports from
// "../c2pa-shape.js" working.

export {
  getActiveManifest,
  type AssertionShape,
  type IngredientShape,
  type ManifestShape,
  type ManifestStoreShape,
  type SignatureInfoShape,
} from "@realreel/c2pa-trust-core";
