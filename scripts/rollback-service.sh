#!/usr/bin/env bash
#
# Roll Cloud Run traffic back to a known-good revision of a service in this repo;
# DEPLOY_ENV picks which one. Cloud Run keeps prior revisions for 90 days, so a
# bad deploy reverts in seconds at the traffic layer — no rebuild. For the
# verifier, see verifier/OPERATIONS.md § Rollback for the decision tree (and what
# rollback does NOT undo: trust-list/DB/edge-secret changes).
#
# Usage:
#   make rollback-verifier                                    # list revisions
#   make rollback-verifier REV=realreel-verifier-00007-abc    # shift traffic
#   make rollback-ocsp-leaf [REV=…]
#   DEPLOY_ENV=verifier/deploy.env scripts/rollback-service.sh [<revision>]

set -euo pipefail

ENV_FILE="${DEPLOY_ENV:-}"

die() { printf '\033[31merror:\033[0m %s\n' "$*" >&2; exit 1; }

[ -n "${ENV_FILE}" ] || die "set DEPLOY_ENV to the service's deploy.env (e.g. DEPLOY_ENV=verifier/deploy.env), or use that service's make target"
[ -f "${ENV_FILE}" ] || die "config not found: ${ENV_FILE}"
# shellcheck disable=SC1090
set -a; . "${ENV_FILE}"; set +a

# deploy.env always lives in the service's own directory, and the make targets
# are named after it — so this recovers the target to suggest below.
SERVICE_DIR="$(basename "$(dirname "${ENV_FILE}")")"

: "${GCP_PROJECT:?set GCP_PROJECT in deploy.env}"
: "${GCP_REGION:?set GCP_REGION in deploy.env}"
: "${CLOUD_RUN_SERVICE:?set CLOUD_RUN_SERVICE in deploy.env}"

command -v gcloud >/dev/null || die "gcloud not found on PATH"

REV="${1:-}"
if [ -z "${REV}" ]; then
  echo "Recent revisions for ${CLOUD_RUN_SERVICE} (most recent first):"
  echo
  gcloud run revisions list \
    --service="${CLOUD_RUN_SERVICE}" \
    --region="${GCP_REGION}" --project="${GCP_PROJECT}" \
    --limit=10
  echo
  echo "Re-run with a revision name to send it 100% of traffic, e.g.:"
  echo "  make rollback-${SERVICE_DIR} REV=${CLOUD_RUN_SERVICE}-00007-abc"
  exit 0
fi

printf '\033[36m==>\033[0m Sending 100%% of traffic to %s\n' "${REV}"
gcloud run services update-traffic "${CLOUD_RUN_SERVICE}" \
  --to-revisions="${REV}=100" \
  --region="${GCP_REGION}" --project="${GCP_PROJECT}"
