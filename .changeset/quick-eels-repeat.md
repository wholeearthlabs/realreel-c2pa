---
'@realreel/verifier': patch
---

Raise the supported Node floor to 24, matching the runtime the image has shipped since it moved to `node:24-bookworm-slim`.

`engines` said `>=22` and CI tested on 22 while the container ran 24, so the suite gating verification never exercised the runtime executing it — and 22 entered maintenance-only in October 2025. Node 24 is Active LTS through 2026-10-20 and supported to 2028-04-30. `@types/node` moves to `^24` to match.
