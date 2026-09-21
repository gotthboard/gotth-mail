#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
builder="$root/scripts/build-production-images.sh"

if [ ! -x "$builder" ]; then
  echo 'production image builder is missing or not executable' >&2
  exit 1
fi

expect_reject() {
  if "$builder" "$@" >/dev/null 2>&1; then
    echo "invalid production build contract accepted: $*" >&2
    exit 1
  fi
}

commit=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
state=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa

expect_reject 1.0.0-alpha.0 "$commit" 1790000000 "$state" gotth-mail-contract-test
expect_reject 1.0.0-alpha.1 short 1790000000 "$state" gotth-mail-contract-test
expect_reject 1.0.0-alpha.1 "$commit" not-an-epoch "$state" gotth-mail-contract-test
expect_reject 1.0.0-alpha.1 "$commit" 1790000000 short gotth-mail-contract-test
expect_reject 1.0.0-alpha.1 "$commit" 1790000000 "$state" 'INVALID/TAG'

runtime_smoke="$root/scripts/production-runtime-smoke.sh"
if ! grep -F 'build-production-images.sh' "$runtime_smoke" >/dev/null ||
  grep -F 'VERSION=1.0.0-alpha.1' "$runtime_smoke" >/dev/null ||
  grep -F 'image inspect "$image"' "$runtime_smoke" >/dev/null; then
  echo 'production runtime smoke is not bound to a fresh development build' >&2
  exit 1
fi

reproducibility="$root/scripts/production-reproducibility.sh"
if [ ! -x "$reproducibility" ] ||
  ! grep -F 'GOTTH_MAIL_PRODUCTION_NO_CACHE=1' "$reproducibility" >/dev/null ||
  ! grep -F -- '--provenance=false' "$builder" >/dev/null ||
  ! grep -F 'rewrite-timestamp=true' "$builder" >/dev/null ||
  ! grep -F 'image="$image_repository_base-$role:$version"' "$builder" >/dev/null ||
  ! grep -F 'info -e "${package_specs[@]}"' "$builder" >/dev/null; then
  echo 'independent production image reproducibility gate is missing' >&2
  exit 1
fi

printf '%s\n' 'production build contract rejection checks passed'
