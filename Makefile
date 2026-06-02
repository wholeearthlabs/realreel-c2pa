# Convenience targets for the realreel-c2pa monorepo.
#
# npm and Deno are the canonical interfaces; these targets just wrap them so
# there's one entry point across the Node workspaces (trust-core, verifier,
# native) and the Deno workspace (ca).

.PHONY: test test-trust-core test-verifier test-ca typecheck verify-trust-anchors verifier-dev

# Run every test suite (trust-core + verifier + ca).
test:
	npm test

test-trust-core:
	npm run test:trust-core

test-verifier:
	npm run test:verifier

test-ca:
	npm run test:ca

# Typecheck the verifier (src) and the native TypeScript bridge.
typecheck:
	npm run typecheck:verifier
	cd native && npx tsc --noEmit

# Validate the vendored trust-anchor PEM chains.
verify-trust-anchors:
	cd verifier && npx tsx scripts/audit-trust-anchors.ts

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
