---
"@realreel/photo-attest": minor
---

A Stage-2 `c2pa.orientation` action can now declare a horizontal mirror. Its parameters take `org.realreel.flip: "horizontal"` alongside or instead of `org.realreel.angle` (new exported type `OrientationParameters`). When both are present, the clockwise rotation applies first and the mirror then flips the rotated result across its vertical axis. One action carries both because spec 2.4 §18.15.1 leaves the order of the actions array unspecified.

Both signers now copy an action's `description` into the manifest when the caller supplies a non-empty one, at the action's top level as the v2 CDDL places it (§18.15.4.1). Previously only `parameters` and `digitalSourceType` were copied, so a supplied `description` was dropped. The `Stage2Action` type accepts it on `c2pa.orientation`.
