#!/usr/bin/env bash
#
# Lint + format-check every Deno service in the repo.
#
# Deno's config is per-directory (each service keeps its own deno.json so their
# node_modules/.deno caches stay separate — see ca/deno.json), so this walks the
# services rather than linting from the root: a root-level `deno lint` would
# miss each service's rule config.
#
# Formatting is scoped to TypeScript. The markdown here is hand-wrapped prose
# and hand-aligned tables, and `deno fmt` reflows both, so every deno.json
# excludes **/*.md from fmt.
#
# Usage:
#   scripts/lint-deno.sh          # check   (CI, `npm run lint`)
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
