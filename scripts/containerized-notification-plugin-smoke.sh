#!/bin/sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
COMPOSE="$ROOT/compose/reference/docker-compose.yml"
PROJECT=${GMF_NOTIFICATION_PLUGIN_SMOKE_PROJECT:-gmf-notification-plugin-smoke}
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
    $DOCKER compose -p "$PROJECT" -f "$COMPOSE" logs --no-color --tail=160 notification-plugin >&2 || true
  fi
  $DOCKER compose -p "$PROJECT" -f "$COMPOSE" down -v --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT
$DOCKER compose -p "$PROJECT" -f "$COMPOSE" down -v --remove-orphans >/dev/null 2>&1 || true
$DOCKER compose -p "$PROJECT" -f "$COMPOSE" up -d --build notification-plugin
for i in $(seq 1 90); do
  if $DOCKER compose -p "$PROJECT" -f "$COMPOSE" build test-runner
$DOCKER compose -p "$PROJECT" -f "$COMPOSE" run --rm -T --no-deps test-runner sh -lc 'nc -z notification-plugin 9443' >/dev/null 2>&1; then break; fi
  [ "$i" = 90 ] && { echo "timeout waiting for notification-plugin:9443" >&2; exit 1; }
  sleep 1
done
$DOCKER compose -p "$PROJECT" -f "$COMPOSE" run --rm -T --no-deps \
  -e GMF_LIVE_PLUGIN_ENDPOINT=notification-plugin:9443 \
  -e GMF_LIVE_PLUGIN_NAME=telegram-notification-sink \
  -e GMF_LIVE_PLUGIN_TOKEN=dev-plugin-token \
  test-runner go test -count=1 ./internal/plugin ./internal/notification ./internal/notifyruntime -run 'TestLivePluginControlOverGRPC|TestLiveNotificationBackendOverGRPC|TestRuntimeCommandProvider|TestTelegramReceiver|TestApprovalExecutor'
echo "containerized notification plugin gRPC/backend smoke passed"
