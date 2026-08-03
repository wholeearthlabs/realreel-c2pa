---
'@realreel/verifier': patch
---

State the non-shared-`ArrayBuffer` requirement in the App Attest hash helpers' types instead of leaving it implicit.

`webcrypto.subtle.digest` rejects a view onto a `SharedArrayBuffer` at runtime (`TypeError: ... is a view on a SharedArrayBuffer, which is not allowed`). `sha256` in `src/attestation/pki-node.ts` declared its input as the unparameterised `Uint8Array`, which admits that shape, so the constraint was enforced only by Node — and only at request time. It now takes and returns `Uint8Array<ArrayBuffer>`, and `concat` reports the fresh, never-shared buffer it actually allocates. No cast, no copy, no change to what bytes are hashed.

This is also what `@types/node@26` began rejecting at compile time; the verifier now typechecks clean under both `^24` (what it ships on) and `26`.
