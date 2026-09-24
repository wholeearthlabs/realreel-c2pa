---
"@realreel/verifier": patch
---

Runtime dependency bumps: `@contentauth/c2pa-node` 0.9.1 → 0.9.7 and `@contentauth/c2pa-types` 0.7.3 → 0.7.4. The embedded engine moves from c2pa-rs 0.90.15 to 0.90.22, and the crJSON harness's `c2patool` moves with it, 0.27.15 → 0.27.22, so the validator and the engine stay on the same c2pa-rs patch (`ci.yml`, the Dockerfile's `crjson-harness` stage, `ENGINE_C2PA_RS`, the pin test and the `CRJSON_HARNESS.md` table). The regenerated goldens differ only in `jsonGenerator.version`; no validation result moved.

The seven intervening c2pa-rs releases are backports: ingredient manifest-label collision handling (spec 2.4 §18.16.12, 0.90.19), the BMFF Merkle-map chunk-index overflow guard (0.90.16), the update-manifest / local_id / JPEG XL / resource-path hardening merged as #2579 (0.90.17), and the v3-ingredient serializer change of #2429 (0.90.16), which does not yet lift the crJSON co-presence limitation recorded in `crjson-harness.test.ts` — only its error text changed. ZIP support (0.90.20) is new surface the MIME allowlist keeps off the verify path.

Not taken: c2pa-node 0.9.8 (c2pa-rs 0.91.0, 2026-09-21). It carries the online-OCSP corrections (responder authorization #2542/#2616, issuing-CA revocation via AIA #2615, status-kind classification #2620) and follows HTTP redirects with the allow-list re-checked per hop (#2433; 0.90.x does not follow them at all), but no `c2patool` release embeds 0.91.0 yet, and the harness requires both sides on one c2pa-rs minor. Move to it once `c2patool` ships a 0.91 build.

c2pa-node 0.9.6 deprecates the raw settings string in favour of `Context` (no runtime warning). The verifier keeps the string: the same document is handed to `c2patool --settings` by the harness.
