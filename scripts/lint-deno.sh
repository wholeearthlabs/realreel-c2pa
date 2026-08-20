#!/usr/bin/env bash
#
# Lint + format-check every Deno service.
#
# Walks the services rather than linting from the root: Deno resolves config
# per-directory, so a root-level `deno lint` would miss each service's rules.
#
#   scripts/lint-deno.sh          # check   (`npm run lint`)
#   scripts/lint-deno.sh --fix    # rewrite (`npm run lint:fix`)

set -uo pipefail

cd "$(dirname "$0")/.."

SERVICES=(ca ocsp ocsp-leaf pki)

FIX=0
[[ "${1:-}" == "--fix" ]] && FIX=1

if ! command -v deno >/dev/null 2>&1; then
  echo "error: deno not found — install Deno >= 2 (https://deno.com)" >&2
  exit 1
fi

failed=()

for svc in "${SERVICES[@]}"; do
  echo "==> $svc"
  ok=1

  if (( FIX )); then
    ( cd "$svc" && deno lint --fix ) || ok=0
    ( cd "$svc" && deno fmt ) || ok=0
  else
    ( cd "$svc" && deno lint ) || ok=0
    ( cd "$svc" && deno fmt --check ) || ok=0
  fi

  (( ok )) || failed+=("$svc")
done

if (( ${#failed[@]} )); then
  echo
  echo "FAILED: ${failed[*]}" >&2
  (( FIX )) || echo "run 'npm run lint:fix' to apply what's auto-fixable" >&2
  exit 1
fi

echo
echo "all Deno services clean (${SERVICES[*]})"
