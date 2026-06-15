#!/usr/bin/env bash
#
# Promote an attested verifier image (GHCR) to Artifact Registry and deploy it
# to Cloud Run.
#
# This is an IMAGE-ONLY deploy: env vars, secrets, the runtime service account,
# scaling, and IAM are all preserved from the current revision — `gcloud run
# deploy` only changes the fields you pass. Use the full DEPLOY.md flow when you
# need to change configuration, not just ship a new version.
#
# It deploys the EXACT image your release workflow published and attested
# (.github/workflows/publish-verifier-image.yml), verifying SLSA provenance
# first, then copying GHCR -> Artifact Registry by digest (Cloud Run can't pull
# GHCR directly). The deployed bytes are the audited bytes.
#
# Usage:
#   verifier/scripts/deploy.sh <verifier-tag> [-y]    # e.g. verifier-v0.5.0
#   make deploy-verifier TAG=verifier-v0.5.0
#
# Config: verifier/deploy.env (copy from verifier/deploy.env.example).
#
# Prerequisites (one-time, on your machine):
#   - gcloud authenticated with deploy rights on the verifier project
#   - docker configured for Artifact Registry:
#       gcloud auth configure-docker <region>-docker.pkg.dev
#   - gh authenticated (for provenance verification)
#   - read access to the GHCR image. If the package is private, log docker in:
#       echo "$GHCR_TOKEN" | docker login ghcr.io -u <user> --password-stdin
#     (a token with read:packages), or make the package public on GitHub. A
#     public package also satisfies DEPLOY.md's "anyone can pull" transparency
#     claim and needs no login.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="${DEPLOY_ENV:-${SCRIPT_DIR}/../deploy.env}"

die()  { printf '\033[31merror:\033[0m %s\n' "$*" >&2; exit 1; }
info() { printf '\033[36m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[33mwarn:\033[0m %s\n' "$*" >&2; }

[ -f "${ENV_FILE}" ] || die "config not found: ${ENV_FILE}
  copy ${SCRIPT_DIR}/../deploy.env.example to deploy.env and fill it in."
# shellcheck disable=SC1090
set -a; . "${ENV_FILE}"; set +a

# --- args ---
GIT_TAG="${1:-}"
[ -n "${GIT_TAG}" ] || die "usage: $(basename "$0") <verifier-tag> [-y]   e.g. verifier-v0.5.0"
case "${GIT_TAG}" in
  verifier-v*) ;;
  *) die "tag must be a full verifier release tag, e.g. verifier-v0.5.0 (got '${GIT_TAG}')" ;;
esac
# VERSION is the bare semver the published image is tagged with
# (docker/metadata-action strips the verifier-v prefix).
VERSION="${GIT_TAG#verifier-v}"

ASSUME_YES=0
case "${2:-}" in -y|--yes) ASSUME_YES=1 ;; esac

# --- required config ---
: "${GHCR_IMAGE:?set GHCR_IMAGE in deploy.env}"
: "${GAR_IMAGE:?set GAR_IMAGE in deploy.env}"
: "${GCP_PROJECT:?set GCP_PROJECT in deploy.env}"
: "${GCP_REGION:?set GCP_REGION in deploy.env}"
: "${CLOUD_RUN_SERVICE:?set CLOUD_RUN_SERVICE in deploy.env}"
: "${ATTEST_REPO:?set ATTEST_REPO in deploy.env}"
VERIFY_PROVENANCE="${VERIFY_PROVENANCE:-true}"

# --- tooling preflight ---
command -v gcloud >/dev/null || die "gcloud not found on PATH"
command -v docker >/dev/null || die "docker not found on PATH"
docker buildx version >/dev/null 2>&1 || die "docker buildx not available (needed for registry-to-registry copy)"

# Confirm gcloud has an active credentialed account — the deploy runs as it.
# Local read, no network; fails fast here instead of deep in `gcloud run deploy`.
GCLOUD_ACCOUNT="$(gcloud auth list --filter=status:ACTIVE --format='value(account)' 2>/dev/null || true)"
[ -n "${GCLOUD_ACCOUNT}" ] || die "not authenticated with gcloud — run: gcloud auth login"

# --- 1. resolve the immutable digest of the GHCR tag ---
info "Resolving digest of ${GHCR_IMAGE}:${VERSION}"
DIGEST="$(docker buildx imagetools inspect "${GHCR_IMAGE}:${VERSION}" --format '{{.Manifest.Digest}}')" \
  || die "could not read ${GHCR_IMAGE}:${VERSION}. Check, in order:
    - is '${GIT_TAG}' pushed and has the publish-verifier-image workflow finished?
    - if the GHCR package is private, log docker in:
        echo \"\$GHCR_TOKEN\" | docker login ghcr.io -u <user> --password-stdin"
[ -n "${DIGEST}" ] || die "empty digest for ${GHCR_IMAGE}:${VERSION}"

# --- 2. verify SLSA build provenance of the EXACT digest we'll ship ---
if [ "${VERIFY_PROVENANCE}" = "true" ]; then
  command -v gh >/dev/null || die "gh not found (needed for provenance verification; set VERIFY_PROVENANCE=false in deploy.env to skip)"
  info "Verifying build provenance of ${GHCR_IMAGE}@${DIGEST} against ${ATTEST_REPO}"
  gh attestation verify "oci://${GHCR_IMAGE}@${DIGEST}" --repo "${ATTEST_REPO}" \
    || die "provenance verification FAILED for ${GHCR_IMAGE}@${DIGEST} — refusing to deploy"
else
  warn "Skipping provenance verification (VERIFY_PROVENANCE=${VERIFY_PROVENANCE})"
fi

# --- plan + confirm ---
cat <<EOF

  Deploy plan
    release tag  : ${GIT_TAG}
    source image : ${GHCR_IMAGE}:${VERSION}
    digest       : ${DIGEST}
    -> registry  : ${GAR_IMAGE}:${VERSION}
    -> service   : ${CLOUD_RUN_SERVICE}  (${GCP_PROJECT} / ${GCP_REGION})
    deploying as : ${GCLOUD_ACCOUNT}
    env/secrets  : preserved from current revision

EOF
if [ "${ASSUME_YES}" -ne 1 ]; then
  read -r -p "Proceed? [y/N] " reply
  case "${reply}" in y|Y|yes|YES) ;; *) die "aborted" ;; esac
fi

# --- 3. copy GHCR -> Artifact Registry, by digest (exact attested bytes) ---
info "Copying image to Artifact Registry"
docker buildx imagetools create --tag "${GAR_IMAGE}:${VERSION}" "${GHCR_IMAGE}@${DIGEST}"

# --- 4. deploy by digest (immutable; ties the revision to specific bytes) ---
info "Deploying to Cloud Run"
gcloud run deploy "${CLOUD_RUN_SERVICE}" \
  --image="${GAR_IMAGE}@${DIGEST}" \
  --region="${GCP_REGION}" \
  --project="${GCP_PROJECT}"

info "Deployed ${CLOUD_RUN_SERVICE} ${GIT_TAG} (${DIGEST})"
