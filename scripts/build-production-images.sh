#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -ne 5 ]; then
  echo 'usage: build-production-images.sh VERSION SOURCE_COMMIT BUILD_DATE_EPOCH SOURCE_STATE IMAGE_REPOSITORY_BASE' >&2
  exit 2
fi

version=$1
source_commit=$2
build_date_epoch=$3
source_state=$4
image_repository_base=$5
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)

if ! printf '%s\n' "$version" | grep -Eq '^dev$|^1\.0\.0$|^1\.0\.0-(alpha|beta)\.[1-9][0-9]*$'; then
  echo 'invalid production image version' >&2
  exit 2
fi
if ! printf '%s\n' "$source_commit" | grep -Eq '^[0-9a-f]{40}$'; then
  echo 'invalid production source commit' >&2
  exit 2
fi
if ! printf '%s\n' "$build_date_epoch" | grep -Eq '^[1-9][0-9]*$'; then
  echo 'invalid production build epoch' >&2
  exit 2
fi
if ! printf '%s\n' "$source_state" | grep -Eq '^[0-9a-f]{64}$'; then
  echo 'invalid production source-state digest' >&2
  exit 2
fi
if ! printf '%s\n' "$image_repository_base" | grep -Eq '^[a-z0-9][a-z0-9._-]*(/[a-z0-9][a-z0-9._-]*)*$'; then
  echo 'invalid production image repository base' >&2
  exit 2
fi
case "${GOTTH_MAIL_PRODUCTION_NO_CACHE:-0}" in
  0|1) ;;
  *) echo 'GOTTH_MAIL_PRODUCTION_NO_CACHE must be 0 or 1' >&2; exit 2 ;;
esac

head_commit=$(git -C "$root" rev-parse HEAD)
if [ "$head_commit" != "$source_commit" ]; then
  echo 'production source commit does not equal HEAD' >&2
  exit 1
fi
commit_epoch=$(git -C "$root" show -s --format=%ct HEAD)
if [ "$commit_epoch" != "$build_date_epoch" ]; then
  echo 'production build epoch does not equal the source commit time' >&2
  exit 1
fi

actual_state=$("$root/scripts/production-source-state.sh")
if [ "$actual_state" != "$source_state" ]; then
  echo 'production source-state digest does not match the build tree' >&2
  exit 1
fi
if [ "$version" != dev ] && [ -n "$(git -C "$root" status --porcelain=v1 --untracked-files=all)" ]; then
  echo 'release image build requires a clean source tree' >&2
  exit 1
fi

docker_mode=direct
if ! docker info >/dev/null 2>&1; then
  docker_mode=sudo
fi
run_docker() {
  if [ "$docker_mode" = direct ]; then
    SOURCE_DATE_EPOCH="$build_date_epoch" DOCKER_BUILDKIT=1 docker "$@"
  else
    sudo -n env SOURCE_DATE_EPOCH="$build_date_epoch" DOCKER_BUILDKIT=1 docker "$@"
  fi
}

cache_flags=()
if [ "${GOTTH_MAIL_PRODUCTION_NO_CACHE:-0}" = 1 ]; then
  cache_flags+=(--no-cache)
fi

for role in control-plane front postfix dovecot rspamd; do
  image="$image_repository_base-$role:$version"
  expected_user=1000:1000
  package_specs=(ca-certificates=20260909-r0 tzdata=2026d-r0)
  case "$role" in
    control-plane) ;;
    front) package_specs+=(nginx=1.28.3-r7 nginx-mod-mail=1.28.3-r7) ;;
    postfix)
      expected_user=0:0
      package_specs+=(postfix=3.10.13-r0 postfix-pcre=3.10.13-r0 postfix-pgsql=3.10.13-r0)
      ;;
    dovecot)
      expected_user=0:0
      package_specs+=(dovecot=2.4.1-r2 dovecot-lmtpd=2.4.1-r2 dovecot-pgsql=2.4.1-r2 dovecot-pigeonhole-plugin=2.4.1-r2)
      ;;
    rspamd) package_specs+=(rspamd=3.11.1-r2) ;;
  esac
  output_dir=$(mktemp -d -t gotth-mail-production-image.XXXXXX)
  archive="$output_dir/image.tar"
  trap 'rm -rf "$output_dir"' EXIT
  run_docker buildx build --platform linux/amd64 --provenance=false --target "$role" "${cache_flags[@]}" \
    --build-arg VERSION="$version" \
    --build-arg SOURCE_COMMIT="$source_commit" \
    --build-arg BUILD_DATE_EPOCH="$build_date_epoch" \
    --build-arg SOURCE_DATE_EPOCH="$build_date_epoch" \
    --build-arg SOURCE_STATE="$source_state" \
    --output "type=docker,name=$image,dest=$archive,rewrite-timestamp=true" \
    -f "$root/build/production/Dockerfile" "$root"
  run_docker image load --input "$archive" >/dev/null
  rm -rf "$output_dir"
  trap - EXIT

  inspected=$(run_docker image inspect --format \
    '{{.Id}} {{index .Config.Labels "com.gotth.mail.role"}} {{index .Config.Labels "org.opencontainers.image.version"}} {{index .Config.Labels "org.opencontainers.image.revision"}} {{index .Config.Labels "com.gotth.mail.source-state"}} {{.Config.User}} {{json .Config.Entrypoint}}' \
    "$image")
  read -r image_id image_role image_version image_revision image_state image_user image_entrypoint <<<"$inspected"
  if [ "$image_role" != "$role" ] || [ "$image_version" != "$version" ] ||
    [ "$image_revision" != "$source_commit" ] || [ "$image_state" != "$source_state" ] ||
    [ "$image_user" != "$expected_user" ] ||
    [ "$image_entrypoint" != '["/usr/local/bin/gotth-mail-entrypoint"]' ]; then
    echo "production image identity mismatch for $role" >&2
    exit 1
  fi
  if ! run_docker run --rm --network none --read-only --cap-drop ALL \
    --security-opt no-new-privileges --entrypoint /sbin/apk "$image" \
    info -e "${package_specs[@]}" >/dev/null; then
    echo "production package contract mismatch for $role" >&2
    exit 1
  fi
  printf '%s %s %s\n' "$role" "$image_id" "$image"
done
