#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -ne 1 ]; then
  echo 'usage: production-reproducibility.sh VERSION' >&2
  exit 2
fi

version=$1
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
source_commit=$(git -C "$root" rev-parse HEAD)
build_date_epoch=$(git -C "$root" show -s --format=%ct HEAD)
source_state=$("$root/scripts/production-source-state.sh")
repository_base_a="gotth-mail-repro-a-${source_state:0:12}-$$"
repository_base_b="gotth-mail-repro-b-${source_state:0:12}-$$"
roles=(control-plane front postfix dovecot rspamd)
images=()
for role in "${roles[@]}"; do
  images+=("$repository_base_a-$role:$version" "$repository_base_b-$role:$version")
done

docker_mode=direct
if ! docker info >/dev/null 2>&1; then
  docker_mode=sudo
fi
run_docker() {
  if [ "$docker_mode" = direct ]; then
    docker "$@"
  else
    sudo -n docker "$@"
  fi
}

cleanup() {
  for image in "${images[@]}"; do
    run_docker image rm -f "$image" >/dev/null 2>&1 || true
  done
}
trap cleanup EXIT
cleanup

GOTTH_MAIL_PRODUCTION_NO_CACHE=1 "$root/scripts/build-production-images.sh" \
  "$version" "$source_commit" "$build_date_epoch" "$source_state" "$repository_base_a"
GOTTH_MAIL_PRODUCTION_NO_CACHE=1 "$root/scripts/build-production-images.sh" \
  "$version" "$source_commit" "$build_date_epoch" "$source_state" "$repository_base_b"

for role in "${roles[@]}"; do
  image_a="$repository_base_a-$role:$version"
  image_b="$repository_base_b-$role:$version"
  id_a=$(run_docker image inspect --format '{{.Id}}' "$image_a")
  id_b=$(run_docker image inspect --format '{{.Id}}' "$image_b")
  if [ "$id_a" != "$id_b" ]; then
    echo "non-reproducible production image for $role: $id_a != $id_b" >&2
    exit 1
  fi
  case "$role" in
    control-plane) paths=(/usr/local/bin/gotth-mail /usr/local/bin/gotth-mail-entrypoint /usr/local/bin/gotth-mail-health) ;;
    postfix) paths=(/usr/local/bin/gotth-mail-postfix-gate /usr/local/bin/gotth-mail-entrypoint /usr/local/bin/gotth-mail-health) ;;
    *) paths=(/usr/local/bin/gotth-mail-entrypoint /usr/local/bin/gotth-mail-health) ;;
  esac
  binaries_a=$(run_docker run --rm --entrypoint sha256sum "$image_a" "${paths[@]}")
  binaries_b=$(run_docker run --rm --entrypoint sha256sum "$image_b" "${paths[@]}")
  if [ "$binaries_a" != "$binaries_b" ]; then
    echo "non-reproducible production binaries for $role" >&2
    exit 1
  fi
  printf '%s %s\n' "$role" "$id_a"
  printf '%s\n' "$binaries_a"
done

printf '%s\n' 'production image reproducibility passed'
