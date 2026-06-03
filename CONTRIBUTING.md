# Contributing

Thanks for your interest in RealReel's open C2PA stack. This repository contains
the cryptographic **signing** and **verification** code behind RealReel,
published for transparency and community review. The RealReel application itself
remains closed-source; this is the part we want anyone to be able to inspect,
learn from, and build trust in.

## Ground rules

- This is **security-sensitive** code. Favor clarity, small focused changes, and
  tests over cleverness.
- By contributing, you agree that your contributions are licensed under the
  project's **Apache License 2.0** (see `LICENSE`).
- **Do not** report security vulnerabilities in public issues — see
  [`SECURITY.md`](./SECURITY.md).

## Repository layout

See the [workspaces table in `README.md`](./README.md#workspaces) for what each
workspace is, plus per-workspace build and test instructions.

## Pull requests

- Keep PRs focused and describe the change **and its security rationale**.
- Add or update tests; keep the existing suites green.
- Note any change that affects the trust model, the wire format, or a public
  interface.
- If your change affects a **published package** (`@realreel/c2pa-trust-core` or
  `@realreel/photo-attest`), include a changeset: run `npx changeset`, pick the
  package(s) and bump, and commit the generated `.changeset/*.md`. Changes to
  `verifier/` and `ca/` (which deploy from source) don't need one.
  