---
"@realreel/verifier": patch
---

Regenerate the device fixtures on a post-cutover production build (app 0.1.6): `realreel-uploaded.jpg` (now exercising `c2pa.orientation` + the signed general locationLabel), `realreel-drained.jpg`, and a matched `pixel-og.jpg`/`pixel-uploaded.jpg` pair (Ultra HDR parent). Deletes the retired-action test shims and the drained-fixture schema special case. The crJSON harness now serializes with canonical key order — c2pa-rs emits flattened maps (`claim_generator_info` vendor fields) in per-invocation hash order, which broke byte-determinism.
