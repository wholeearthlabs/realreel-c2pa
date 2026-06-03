# AGENTS.md

Guidance for AI coding agents (and humans) working in this repository.

This is the open-source C2PA **signing and verification** stack behind RealReel.
It is **security-sensitive cryptographic code** — treat every change accordingly.

## Golden rules

1. **Behavior-preserving by default.** Do not change cryptographic, protocol, or
   trust-model behavior unless that is explicitly the task. Prefer the smallest
   change that works.
2. **Keep every suite green.** Run the tests (see _Commands_) and add or update
   tests alongside any change.
3. **Never weaken a security invariant to make a test pass.** If an invariant is
   in your way, stop and surface it — don't route around it.
4. **No secrets, ever.** The CA signing key is **not** in this repo (it lives in
   an HSM); `verifier/trust-sources/` holds only **public** certificates.
5. **Report vulnerabilities privately** (see `SECURITY.md`) — never in a public
   issue or PR.

## Repository layout

| Workspace     | What it is                                                    | Runtime         |
| ------------- | ------------------------------------------------------------ | --------------- |
| `trust-core/` | Shared trust list, action policies, C2PA manifest shapes.    | TypeScript      |
| `verifier/`   | C2PA verification microservice (chain, revocation, attest).  | TypeScript/Node |
| `native/`     | Hardware-backed capture-signing module + TS bridge.          | Swift / Kotlin  |
| `ca/`         | Enrollment / certificate-authority + challenge functions.    | TypeScript/Deno |

## Commands

```bash
npm install                         # install + link npm workspaces (Node >= 22)
npm test                            # run everything (trust-core + verifier + ca)
npm run test:trust-core             # vitest
npm run test:verifier               # vitest
npm run typecheck:verifier          # tsc, src only
npm run test:ca                     # deno test — needs Deno >= 2
( cd native && npx tsc --noEmit )   # typecheck the native TS bridge
```

Binary test fixtures live in **Git LFS**. If `verifier/__tests__/fixtures/*`
look like ~130-byte text stubs, run `git lfs pull`.

## Conventions

- TypeScript in `trust-core` / `verifier` / the `native` bridge; Deno-flavored
  TypeScript in `ca`; Swift + Kotlin in `native`.
- The verifier abstracts its datastore behind ports (`verifier/src/ports.ts`):
  an integrator swaps the backend by passing a `datastore` to `verify()`. The
  default is the Postgres adapter in `verifier/src/db.ts`.
- Comments should earn their place — explain non-obvious **why** (especially
  security invariants and external-spec references), not the obvious **what**.

## Releasing

The two **published** packages — `@realreel/c2pa-trust-core` (`trust-core/`) and
`@realreel/photo-attest` (`native/`) — are versioned with
[Changesets](https://github.com/changesets/changesets). For any change to either
package's published code, add a changeset and commit the generated file with
your change:

```bash
npx changeset                       # pick the package(s) + semver bump + changelog line
```

## Don't

- Don't run, assume, or require a native/device build here — Swift/Kotlin need a
  full Expo + Xcode/Gradle toolchain and can't be compiled in this repo.
- Don't add a dependency on the closed-source RealReel application.
- Don't relax attestation, revocation, or certificate-chain-validation checks.

See `CONTRIBUTING.md`, `TRUST_ARCHITECTURE.md`, and `SECURITY.md` for more.
