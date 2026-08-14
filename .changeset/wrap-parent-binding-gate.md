---
"@realreel/c2pa-trust-core": patch
"@realreel/photo-attest": patch
---

Enforce the wrapped parent's hard binding end-to-end, closing the wrap-mode tamper gap (an edited capture with an intact, chain-valid manifest previously verified as Trusted).

trust-core: new shared binding policy (`findBindingFailureCodes`, `findContentTamperCodes`, `findRecordedBindingViolation`) plus the shared `ALLOWED_UPLOAD_MIME_TYPES`, typed `validation_status` / `validation_results` / ingredient recorded-results shapes, and the `PARENT_BINDING_FAILED` error code. Enforcement is unconditional and fail-closed — content whose binding cannot be verified is not accepted. Known accepted consequence: released mobile SDKs (c2pa-ios ≤ 0.0.12, c2pa-android ≤ 0.0.10, both pre c2pa-rs #2434) record a false `bmffHash.mismatch` for genuine Pixel videos, so wrap-mode Pixel VIDEOS are rejected until the SDK bump; acceptance restores itself once bumped SDKs record clean verdicts.

Verifier (deploys with this release): rejects `PARENT_BINDING_FAILED` unless the Stage-2 `c2pa.ingredient.v3` recorded results carry the positive binding match and no binding failure (fail-closed on an absent record); resolves the PARENT's trust source and enforces `wrap_parent_only` (previously decorative — any pooled anchor, including the TSA roots, could vouch for a "camera"); allowlists + magic-sniffs the client-supplied mimeType before it selects a c2pa-rs asset handler.

photo-attest: doc-only — the recorded ingredient `validationResults` contract now notes the binding portion is enforced server-side.
