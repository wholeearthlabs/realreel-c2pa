# Convenience targets for the realreel-c2pa monorepo.
#
# npm and Deno are the canonical interfaces; these targets just wrap them so
# there's one entry point across the Node workspaces (trust-core, verifier,
# native) and the Deno workspace (ca).

.PHONY: test test-trust-core test-verifier test-ca lint lint-fix typecheck verify-trust-anchors verify-attestation-roots verifier-dev deploy-verifier rollback-verifier deploy-ocsp-leaf rollback-ocsp-leaf

# Run every test suite (trust-core + verifier + ca).
test:
	npm test

test-trust-core:
	npm run test:trust-core

test-verifier:
	npm run test:verifier

test-ca:
	npm run test:ca

# Lint + format-check every Deno service (ca, ocsp, ocsp-leaf, pki).
lint:
	npm run lint

lint-fix:
	npm run lint:fix

# Typecheck the verifier (src) and the native TypeScript bridge.
typecheck:
	npm run typecheck:verifier
	cd native && npx tsc --noEmit

# Validate the vendored trust-anchor PEM chains.
verify-trust-anchors:
	cd verifier && npx tsx scripts/audit-trust-anchors.ts

# Watch the pinned enrollment attestation roots (Google + Apple) for expiry.
verify-attestation-roots:
	cd ca && deno run --quiet --allow-read --allow-env --allow-net scripts/audit-attestation-roots.ts

# Run the verifier locally. Expects a local Postgres reachable at the URL below
# with the verifier schema applied. For anything real, copy verifier/.env.example
# and supply your own values.
verifier-dev:
	cd verifier && \
		DATABASE_URL="postgres://postgres:postgres@127.0.0.1:54322/postgres" \
		VERIFIER_SHARED_SECRET="dev-shared-secret-not-for-prod" \
		ASSET_STORAGE_HOST_REGEX="^http://(127\.0\.0\.1|localhost):54321/storage/v1/object/sign/" \
		ASSET_STORAGE_HOST_ALLOWLIST="127.0.0.1:54321,localhost:54321" \
		PORT=8787 \
		npm run dev

# Promote an already-published, attested image (GHCR) to Artifact Registry and
# deploy it to Cloud Run. Image-only — env/secrets are preserved from the current
# revision. Config lives in <service>/deploy.env (copy from deploy.env.example).
# Pass YES=1 to skip the confirmation prompt.
#   make deploy-verifier  TAG=verifier-v0.5.0
#   make deploy-ocsp-leaf TAG=ocsp-leaf-v0.1.0
# TAG_PREFIX is set here, not in deploy.env: it's fixed by the service's publish
# workflow (its tag trigger + metadata-action pattern), both tracked — so it
# belongs beside them, not in a gitignored per-operator file.
deploy-verifier:
	@test -n "$(TAG)" || { echo "usage: make deploy-verifier TAG=<verifier-tag>   e.g. verifier-v0.5.0"; exit 1; }
	TAG_PREFIX=verifier-v DEPLOY_ENV=verifier/deploy.env scripts/deploy-service.sh "$(TAG)" $(if $(YES),-y,)

deploy-ocsp-leaf:
	@test -n "$(TAG)" || { echo "usage: make deploy-ocsp-leaf TAG=<ocsp-leaf-tag>   e.g. ocsp-leaf-v0.1.0"; exit 1; }
	TAG_PREFIX=ocsp-leaf-v DEPLOY_ENV=ocsp-leaf/deploy.env scripts/deploy-service.sh "$(TAG)" $(if $(YES),-y,)

# Roll Cloud Run traffic back to a known-good revision. No REV lists revisions.
#   make rollback-verifier                                    # list
#   make rollback-verifier  REV=realreel-verifier-00007-abc   # shift traffic
#   make rollback-ocsp-leaf [REV=realreel-ocsp-leaf-00007-abc]
rollback-verifier:
	DEPLOY_ENV=verifier/deploy.env scripts/rollback-service.sh $(REV)

rollback-ocsp-leaf:
	DEPLOY_ENV=ocsp-leaf/deploy.env scripts/rollback-service.sh $(REV)
