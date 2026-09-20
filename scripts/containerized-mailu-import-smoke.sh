#!/bin/sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
COMPOSE="$ROOT/compose/reference/docker-compose.yml"
PROJECT=${GOTTH_MAIL_MAILU_SMOKE_PROJECT:-gotth-mail-mailu-import-smoke-${USER:-test}-$$}
DOCKER=${DOCKER:-docker}
if ! $DOCKER ps >/dev/null 2>&1; then
  if command -v sudo >/dev/null 2>&1 && sudo docker ps >/dev/null 2>&1; then
    DOCKER="sudo docker"
  else
    echo "docker daemon unavailable" >&2
    exit 1
  fi
fi
cleanup() {
  $DOCKER compose -p "$PROJECT" -f "$COMPOSE" --profile mailu-import down -v --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT
cleanup
$DOCKER compose -p "$PROJECT" -f "$COMPOSE" --profile mailu-import up -d mailu-redis mailu-admin
for i in $(seq 1 90); do
  status=$($DOCKER inspect -f '{{.State.Health.Status}}' "${PROJECT}-mailu-admin-1" 2>/dev/null || echo starting)
  [ "$status" = healthy ] && break
  if [ "$status" = unhealthy ]; then
    $DOCKER compose -p "$PROJECT" -f "$COMPOSE" logs --no-color --tail=160 mailu-admin >&2 || true
    exit 1
  fi
  [ "$i" = 90 ] && { $DOCKER compose -p "$PROJECT" -f "$COMPOSE" logs --no-color --tail=160 mailu-admin >&2 || true; exit 1; }
  sleep 2
done
$DOCKER compose -p "$PROJECT" -f "$COMPOSE" exec -T mailu-admin flask mailu domain example.test >/dev/null 2>&1 || true
$DOCKER compose -p "$PROJECT" -f "$COMPOSE" exec -T mailu-admin flask mailu user user example.test gotth-mail-user-password >/dev/null
$DOCKER compose -p "$PROJECT" -f "$COMPOSE" exec -T mailu-admin flask mailu alias alias example.test 'postmaster@example.test,user@example.test' >/dev/null 2>&1 || true
tmpdir=$(mktemp -d)
$DOCKER compose -p "$PROJECT" -f "$COMPOSE" exec -T mailu-admin flask mailu config-export --json > "$tmpdir/config-export.json"
$DOCKER compose -p "$PROJECT" -f "$COMPOSE" exec -T mailu-admin flask mailu config-export --secrets --json > "$tmpdir/config-export-secrets.json"
$DOCKER compose -p "$PROJECT" -f "$COMPOSE" build test-runner
$DOCKER compose -p "$PROJECT" -f "$COMPOSE" run --rm -T --no-deps test-runner go test -count=1 ./internal/ops ./internal/api
python3 - <<'PY' "$tmpdir/config-export-secrets.json"
import json, sys
p=sys.argv[1]
data=json.load(open(p))
assert sorted(data.keys()) == ['alias', 'domain', 'relay', 'user'], data.keys()
users={u['email']: u for u in data['user']}
assert 'user@example.test' in users, users
assert users['user@example.test']['password'].startswith('$bcrypt-sha256$'), users['user@example.test']['password'][:20]
aliases={a['email']: a for a in data['alias']}
assert aliases['alias@example.test']['destination'] == ['postmaster@example.test','user@example.test'], aliases
PY
echo "containerized Mailu import smoke passed"
