#!/usr/bin/env bash
#
# Roll Cloud Run traffic back to a known-good verifier revision. Cloud Run keeps
# prior revisions for 90 days, so a bad deploy reverts in seconds at the traffic
# layer — no rebuild. See verifier/OPERATIONS.md § Rollback for the decision
# tree (and what rollback does NOT undo: trust-list/DB/edge-secret changes).
#
# Usage:
#   verifier/scripts/rollback.sh                 # list recent revisions
#   verifier/scripts/rollback.sh <revision>      # send 100% traffic to <revision>
#   make rollback-verifier
#   make rollback-verifier REV=realreel-verifier-00007-abc
#
# Config: verifier/deploy.env (copy from verifier/deploy.env.example).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="${DEPLOY_ENV:-${SCRIPT_DIR}/../deploy.env}"

[ -f "${ENV_FILE}" ] || { printf '\033[31merror:\033[0m config not found: %s\n' "${ENV_FILE}" >&2; exit 1; }
# shellcheck disable=SC1090
set -a; . "${ENV_FILE}"; set +a

: "${GCP_PROJECT:?set GCP_PROJECT in deploy.env}"
: "${GCP_REGION:?set GCP_REGION in deploy.env}"
: "${CLOUD_RUN_SERVICE:?set CLOUD_RUN_SERVICE in deploy.env}"

command -v gcloud >/dev/null || { echo "gcloud not found on PATH" >&2; exit 1; }

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
  echo "  make rollback-verifier REV=${CLOUD_RUN_SERVICE}-00007-abc"
  exit 0
fi

printf '\033[36m==>\033[0m Sending 100%% of traffic to %s\n' "${REV}"
gcloud run services update-traffic "${CLOUD_RUN_SERVICE}" \
  --to-revisions="${REV}=100" \
  --region="${GCP_REGION}" --project="${GCP_PROJECT}"
