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

# Sequencing equipment only: real generator/tool identity has separate tests.
# No Docker daemon, image build, git commit or network is used here.
stage=$(mktemp -d "${TMPDIR:-/tmp}/gotth-build-contract.XXXXXXXX")
trap 'rm -rf -- "$stage"' EXIT
mkdir -p "$stage/tree/scripts" "$stage/bin"
cp "$builder" "$stage/tree/scripts/build-production-images.sh"
cat > "$stage/tree/scripts/production-source-state.sh" <<'STATE'
#!/usr/bin/env bash
printf '%s\n' "${STUB_STATE:-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa}"
STATE
cat > "$stage/tree/scripts/generate-extension-inventory.sh" <<'GEN'
#!/usr/bin/env bash
[[ $# == 1 && "$1" == --check ]] || exit 97
printf '%s\n' generator >> "$EVENTS"
exit "${GEN_EXIT:-0}"
GEN
cat > "$stage/bin/git" <<'GIT'
#!/usr/bin/env bash
shift 2
case "$1" in
 rev-parse) echo "${STUB_HEAD:-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb}";;
 show) echo 1790000000;;
 status) printf '%s' "${STUB_DIRTY:-}";;
 *) exit 98;;
esac
GIT
cat > "$stage/bin/docker" <<'DOCKER'
#!/usr/bin/env bash
printf '%s\n' "docker $*" >> "$EVENTS"
case "$1 $2" in
 'info ') exit 0;;
 'buildx build')
  role=''; image=''
  while (( $# )); do
   case "$1" in --target) role=$2;shift;; --output) image=${2#type=docker,name=};image=${image%%,dest=*};shift;; esac
   shift
  done
  [[ "$image" == "gotth-mail-contract-test-$role:dev" ]] || exit 96
  ;;
 'image inspect')
  image=${!#};role=${image#gotth-mail-contract-test-};role=${role%:dev}
  user=1000:1000; [[ "$role" == postfix || "$role" == dovecot ]] && user=0:0
  printf '%s\n' "sha256:fixture $role dev bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa $user [\"/usr/local/bin/gotth-mail-entrypoint\"]";;
 'image load'|'run --rm') exit 0;;
 *) exit 95;;
esac
DOCKER
cat > "$stage/bin/sudo" <<'SUDO'
#!/usr/bin/env bash
echo unexpected-sudo >> "$EVENTS"; exit 94
SUDO
chmod +x "$stage/tree/scripts/"*.sh "$stage/bin/"*
export EVENTS="$stage/events"
export PATH="$stage/bin:$PATH"
fixture_builder="$stage/tree/scripts/build-production-images.sh"
for reason in arguments head epoch state dirty; do
 : > "$EVENTS"
 export STUB_HEAD=$commit STUB_STATE=$state STUB_DIRTY=
 version=dev;epoch=1790000000
 case "$reason" in arguments)version=bad;;head)STUB_HEAD=wrong;;epoch)epoch=1790000001;;state)STUB_STATE=wrong;;dirty)version=1.0.0;STUB_DIRTY=' M tracked';;esac
 if "$fixture_builder" "$version" "$commit" "$epoch" "$state" gotth-mail-contract-test > "$stage/reject.log" 2>&1; then echo "accepted $reason" >&2;exit 1;fi
 [[ ! -s "$EVENTS" ]] || { echo "side effect before $reason validation" >&2;exit 1; }
done
export STUB_HEAD=$commit STUB_STATE=$state STUB_DIRTY=
for failure in 1 2 19; do
 : > "$EVENTS"
 if GEN_EXIT=$failure "$fixture_builder" dev "$commit" 1790000000 "$state" gotth-mail-contract-test > "$stage/generator.log" 2>&1; then echo 'failed generation reached success' >&2;exit 1;fi
 [[ "$(cat "$EVENTS")" == generator ]] || { echo 'generator failure did not precede Docker' >&2;exit 1; }
done
: > "$EVENTS"
mv "$stage/tree/scripts/generate-extension-inventory.sh" "$stage/generator.saved"
if "$fixture_builder" dev "$commit" 1790000000 "$state" gotth-mail-contract-test > "$stage/missing.log" 2>&1; then exit 1;fi
[[ ! -s "$EVENTS" ]] || { echo 'missing generator reached Docker' >&2;exit 1; }
mv "$stage/generator.saved" "$stage/tree/scripts/generate-extension-inventory.sh"
: > "$EVENTS"
"$fixture_builder" dev "$commit" 1790000000 "$state" gotth-mail-contract-test > "$stage/success.log" 2>&1
[[ "$(head -n 2 "$EVENTS")" == $'generator\ndocker info' ]] || { echo 'generation not first' >&2;exit 1; }
[[ $(grep -c '^docker buildx build ' "$EVENTS") == 5 ]] || exit 1
[[ $(grep -c '^docker image inspect ' "$EVENTS") == 5 ]] || exit 1
[[ $(grep -c '^docker run --rm ' "$EVENTS") == 5 ]] || exit 1
printf '%s\n' 'production build rejection and stubbed generation-before-Docker sequencing passed'
