#!/usr/bin/env bash
# Build-only, two explicitly named component pairs. Acquisition is a separate reviewed step.
# Complexity (successful run): time O(T+I+O+G), Omega(T+I+O);
# auxiliary space O(1+S), Omega(1); tight Theta not established for delegated
# generator/compiler time G and memory S. T tool bytes, I input bytes, O output
# bytes. Hashing streams with Theta(1) buffers; scratch disk Theta(I+O).
set -euo pipefail
mode=${1:---write}
[[ $# -le 1 && ( "$mode" == --write || "$mode" == --check ) ]] || { echo 'usage: generate-extension-inventory.sh [--write|--check]' >&2; exit 2; }
root=$(cd -- "$(dirname -- "$0")/.." && pwd -P)
: "${TAILWINDCSS_BIN:?TAILWINDCSS_BIN must name the reviewed local executable}"
: "${GO_BIN:?GO_BIN must name Go 1.26.6}"
: "${GOCACHE:?explicit private GOCACHE required}"
: "${GOMODCACHE:?explicit private GOMODCACHE required}"
: "${TMPDIR:?explicit off-root TMPDIR required}"
for command in jq bwrap sha256sum stat getconf; do command -v "$command" >/dev/null || { echo "required local tool unavailable: $command" >&2; exit 1; }; done
for directory in "$GOCACHE" "$GOMODCACHE" "$TMPDIR"; do
 [[ "$directory" == /* && -d "$directory" && ! -L "$directory" && "$(realpath -- "$directory")" == "$directory" && "$(stat -c %u -- "$directory")" == "$(id -u)" ]] || { echo 'cache/temp must be explicit owned canonical directories' >&2; exit 1; }
 # Component-aware disjointness before any tool execution or staging. For
 # path bytes P: O(P), Omega(1) time/space; tight bound varies by match.
 if [[ "$directory" == "$root" || "$directory" == "$root/"* || "$root" == "$directory/"* ]]; then
  echo 'cache/temp source overlap' >&2; exit 1
 fi
 case "$directory" in /|/home|/tmp|/var|/usr|"$HOME"|"$root") echo 'refusing broad writable directory' >&2; exit 1;; esac
done
manifest=$root/tools/renderer/tailwind-standalone.json
jq -e '.version == "4.3.3" and .platform.os == "Linux" and .platform.architecture == "x86_64" and .platform.libc == "glibc" and .tag == "v4.3.3" and .asset_id == 479118279 and .size == 111749248 and .sha256 == "dc61b3ac6b8c9ca874c0cc4c57b2409791a64c5540404ca5f5367360babc313a"' "$manifest" >/dev/null || { echo 'unreviewed tool manifest' >&2; exit 1; }
[[ "$(uname -s)" == Linux && "$(uname -m)" == x86_64 && "$(getconf GNU_LIBC_VERSION)" == "glibc "* ]] || { echo 'unsupported standalone platform' >&2; exit 1; }
[[ "$TAILWINDCSS_BIN" == /* && -f "$TAILWINDCSS_BIN" && -x "$TAILWINDCSS_BIN" && ! -L "$TAILWINDCSS_BIN" ]] || { echo 'TAILWINDCSS_BIN must be an explicit regular executable' >&2; exit 1; }
[[ "$(stat -c %s -- "$TAILWINDCSS_BIN")" == "$(jq -r .size "$manifest")" ]] || { echo 'standalone size mismatch' >&2; exit 1; }
[[ "$(sha256sum -- "$TAILWINDCSS_BIN" | cut -d ' ' -f1)" == "$(jq -r .sha256 "$manifest")" ]] || { echo 'standalone checksum mismatch' >&2; exit 1; }
[[ "$GO_BIN" == /* && -x "$GO_BIN" ]] || { echo 'explicit GO_BIN unavailable' >&2; exit 1; }
export GOENV=off GOTOOLCHAIN=local GOWORK=off GOFLAGS= GOPROXY=off GOSUMDB=sum.golang.org GONOSUMDB= GONOPROXY= GOPRIVATE=
[[ "$("$GO_BIN" env GOVERSION)" == go1.26.6 ]] || { echo 'Go 1.26.6 required' >&2; exit 1; }
stage=$(mktemp -d "$TMPDIR/inventory-generate.XXXXXXXX")
trap 'rm -rf -- "$stage"' EXIT
mkdir -p "$stage/tools/renderer" "$stage/internal/httpui/assets" "$stage/tmp"
cp -- "$root/tools/renderer/go.mod" "$root/tools/renderer/go.sum" "$stage/tools/renderer/"
# templ checks the source module runtime version; this does not merge tool MVS.
cp -- "$root/go.mod" "$root/go.sum" "$stage/"
cp -- "$root/internal/httpui/extensions_inventory.templ" "$root/internal/httpui/extensions_detail.templ" "$stage/internal/httpui/"
cp -- "$root/internal/httpui/assets/extensions-inventory.input.css" "$root/internal/httpui/assets/extensions-detail.input.css" "$stage/internal/httpui/assets/"
# Never trust an environment flag claiming that a parent disabled networking.
# The tool process has read-only source and only staging/private-cache writes.
bwrap --ro-bind / / --bind "$stage" "$stage" --bind "$GOCACHE" "$GOCACHE" --bind "$GOMODCACHE" "$GOMODCACHE" --proc /proc --dev /dev --unshare-net --unshare-pid --die-with-parent /bin/bash -s -- "$stage" "$GO_BIN" "$TAILWINDCSS_BIN" <<'GENERATE'
set -euo pipefail
stage=$1; go=$2; tailwind=$3
export TMPDIR=$stage/tmp GOTMPDIR=$stage/tmp
cd "$stage/tools/renderer"
[[ "$("$go" list -mod=readonly -m -f '{{.Version}}' github.com/a-h/templ)" == v0.3.1020 ]] || { echo 'templ 0.3.1020 required' >&2; exit 1; }
"$go" tool templ generate -path ../.. -f ../../internal/httpui/extensions_inventory.templ -include-version=true -include-timestamp=false
"$go" tool templ generate -path ../.. -f ../../internal/httpui/extensions_detail.templ -include-version=true -include-timestamp=false
cd "$stage"
"$tailwind" -i internal/httpui/assets/extensions-inventory.input.css -o internal/httpui/assets/inventory.css
"$tailwind" -i internal/httpui/assets/extensions-detail.input.css -o internal/httpui/assets/detail.css
GENERATE
for file in internal/httpui/extensions_inventory_templ.go internal/httpui/assets/inventory.css internal/httpui/extensions_detail_templ.go internal/httpui/assets/detail.css; do
 [[ -s "$stage/$file" ]] || { echo 'generator did not produce complete outputs' >&2; exit 1; }
done
if [[ "$mode" == --check ]]; then
 for file in internal/httpui/extensions_inventory_templ.go internal/httpui/assets/inventory.css internal/httpui/extensions_detail_templ.go internal/httpui/assets/detail.css; do
  cmp -s -- "$stage/$file" "$root/$file" || { echo "stale generated output: $file" >&2; exit 1; }
 done
else
 # All four generated files are complete before replacement. Filesystem errors are
 # visible failures, not an atomic multi-file transaction; regenerate after one.
 for file in internal/httpui/extensions_inventory_templ.go internal/httpui/assets/inventory.css internal/httpui/extensions_detail_templ.go internal/httpui/assets/detail.css; do cp -- "$stage/$file" "$root/$file"; done
fi
