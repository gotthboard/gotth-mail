#!/bin/sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
COMPOSE="$ROOT/compose/reference/docker-compose.yml"
PROJECT=${GMF_WEBMAIL_UI_SMOKE_PROJECT:-gmf-webmail-ui-smoke}
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
  rc=$?
  if [ "$rc" -ne 0 ]; then
    $DOCKER compose -p "$PROJECT" -f "$COMPOSE" ps >&2 || true
    $DOCKER compose -p "$PROJECT" -f "$COMPOSE" logs --no-color --tail=160 gophermailforge >&2 || true
  fi
  $DOCKER compose -p "$PROJECT" -f "$COMPOSE" down -v --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT
$DOCKER compose -p "$PROJECT" -f "$COMPOSE" down -v --remove-orphans >/dev/null 2>&1 || true
$DOCKER compose -p "$PROJECT" -f "$COMPOSE" up -d --build gophermailforge
$DOCKER compose -p "$PROJECT" -f "$COMPOSE" build test-runner
for i in $(seq 1 90); do
  if $DOCKER compose -p "$PROJECT" -f "$COMPOSE" run --rm -T --no-deps --use-aliases -e GMF_LIVE_WEBMAIL_UI_URL=http://gophermailforge:8080 test-runner go test -count=1 ./internal/api -run TestLiveContainerWebmailShellReachable >/dev/null 2>&1; then break; fi
  [ "$i" = 90 ] && { echo "timeout waiting for gophermailforge webmail UI" >&2; exit 1; }
  sleep 1
done
$DOCKER compose -p "$PROJECT" -f "$COMPOSE" run --rm -T --no-deps --use-aliases \
  -e GMF_LIVE_WEBMAIL_UI_URL=http://gophermailforge:8080 \
  test-runner go test -count=1 ./internal/api -run TestLiveContainerWebmailShellReachable
echo "containerized custom webmail UI smoke passed"
