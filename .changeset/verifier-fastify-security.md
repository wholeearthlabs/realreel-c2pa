---
"@realreel/verifier": patch
---

Runtime dependency bumps for published security advisories. `fastify` 5.12.1 → 5.12.5 fixes GHSA-9q9j-q6p8-xq58 (header validation bypass), GHSA-hwr6-493r-vm6h (validation bypass via `false` schemas), GHSA-p68q-wchp-6fh7 (malformed URLs reaching encapsulated not-found handlers), GHSA-667r-xxjv-c9mm (request body replacement via an async validation collision) and GHSA-4mh8-r7rc-xpvc (HTTP/2 trailer DoS). Its transitive `find-my-way` moves 9.6.0 → 9.9.0 (HTTP/2 DoS) and `fast-uri` 3.1.2 / 4.1.2 → 3.1.8 / 4.2.1 (host confusion, SSRF and authority-injection fixes); `brace-expansion` 1.1.15 → 1.1.21 (expansion DoS). Also `google-auth-library` 11.0.2 → 11.1.0, `cbor-x` 1.6.5 → 1.6.6 and `yaml` 2.9.0 → 2.9.1.

`@contentauth/c2pa-types` stays at 0.7.4: c2pa-node 0.9.7 pins it exactly, and 0.7.5 is the one c2pa-node 0.9.8 (c2pa-rs 0.91) pins. Dependabot now groups the two so they always move together.
