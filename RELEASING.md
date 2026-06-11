# Releasing

All three workspace packages version through Changesets; what differs is the
release output. Know which one you're cutting.

| Artifact | Dir | Type | Versioning | Release trigger | Output |
| --- | --- | --- | --- | --- | --- |
| `@realreel/c2pa-trust-core` | `trust-core/` | npm package | Changesets | merge the "Version Packages" PR | npm publish (OIDC provenance) |
| `@realreel/photo-attest` | `native/` | npm package | Changesets | merge the "Version Packages" PR | npm publish (OIDC provenance) |
| verifier | `verifier/` | container image | Changesets (private, no publish) | push `verifier-v<semver>` | GHCR image + SLSA provenance |
| ca | `ca/` | Deno functions | — (not a workspace) | deploy-from-source | no versioned release |

## npm packages (Changesets)

`@realreel/c2pa-trust-core` and `@realreel/photo-attest` are versioned with
[Changesets](https://github.com/changesets/changesets).

1. With your change, add a changeset and commit the generated file:

   ```bash
   npx changeset   # pick the package(s) + semver bump + changelog line
   ```

2. Merge to `main`. [`release.yml`](.github/workflows/release.yml) opens (or
   updates) a single "Version Packages" PR that applies the pending bumps and
   changelogs. Every later change that lands on `main` with its own changeset
   re-runs the workflow and **accumulates into the same PR** — so to batch a
   release, just keep merging and leave the PR open.
3. Merge the "Version Packages" PR when you're ready to ship. Only that merge
   publishes — the same workflow pushes every accumulated package to npm via
   Trusted Publishing (OIDC — no stored token, provenance automatic).

## Verifier image (Changesets + git tag)

The verifier is `private`, so Changesets versions it and maintains
`verifier/CHANGELOG.md` but never publishes it — and (per `privatePackages.tag`
in [`.changeset/config.json`](.changeset/config.json)) never auto-tags it.
Versioning is automatic; cutting the image is a deliberate manual tag.

1. With a verifier change, add a changeset (same `npx changeset`) and pick
   `@realreel/verifier`. Merging the "Version Packages" PR bumps
   `verifier/package.json` and writes `verifier/CHANGELOG.md`. Nothing is
   published; no tag is created.
2. When you want to ship an image, tag the bumped version and push:

   ```bash
   git tag verifier-v0.3.0          # match verifier/package.json
   git push origin verifier-v0.3.0
   ```

   The tag triggers
   [`publish-verifier-image.yml`](.github/workflows/publish-verifier-image.yml),
   which builds and pushes `ghcr.io/wholeearthlabs/realreel-verifier:0.3.0`
   (+ `latest`) with SLSA build provenance.

The tag stays manual on purpose: the default `GITHUB_TOKEN` can't trigger the
image workflow, so auto-tagging would need an extra CI credential — and keeping
it manual means a human decides when a production image is cut.

Tagging publishes the attested image; it does **not** deploy to production.
Cloud Run pulls from Artifact Registry — build, push, and deploy per
[`verifier/DEPLOY.md`](verifier/DEPLOY.md).

## ca

`ca/` (Deno functions) isn't an npm workspace, so it's outside Changesets
entirely. No version, no changelog, no tag — it deploys from source.
