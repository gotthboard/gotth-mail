#!/bin/sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
COMPOSE="$ROOT/compose/reference/docker-compose.yml"
PROJECT=${GMF_NOTIFICATION_PLUGIN_SMOKE_PROJECT:-gmf-notification-plugin-smoke-$(date +%s)-$$}
DOCKER=${DOCKER:-docker}
if ! $DOCKER ps >/dev/null 2>&1; then
  if command -v sudo >/dev/null 2>&1 && sudo -n docker ps >/dev/null 2>&1; then
    DOCKER="sudo -n docker"
  else
    echo "docker daemon unavailable" >&2
    exit 1
  fi
fi
cleanup() {
  rc=$?
  trap - EXIT
  if [ "$rc" -ne 0 ]; then
    $DOCKER compose -p "$PROJECT" -f "$COMPOSE" ps >&2 || true
    $DOCKER compose -p "$PROJECT" -f "$COMPOSE" logs --no-color --tail=160 notification-plugin >&2 || true
  fi
  if ! $DOCKER compose -p "$PROJECT" -f "$COMPOSE" down -v --remove-orphans; then
    echo "notification smoke cleanup failed for project $PROJECT" >&2
    [ "$rc" -ne 0 ] || rc=1
  fi
  exit "$rc"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
$DOCKER compose -p "$PROJECT" -f "$COMPOSE" down -v --remove-orphans >/dev/null 2>&1 || true
$DOCKER compose -p "$PROJECT" -f "$COMPOSE" up -d --build notification-plugin
$DOCKER compose -p "$PROJECT" -f "$COMPOSE" build test-runner
for i in $(seq 1 90); do
  if $DOCKER compose -p "$PROJECT" -f "$COMPOSE" run --rm -T --no-deps test-runner sh -lc 'nc -z notification-plugin 9443' >/dev/null 2>&1; then break; fi
  [ "$i" = 90 ] && { echo "timeout waiting for notification-plugin:9443" >&2; exit 1; }
  sleep 1
done
$DOCKER compose -p "$PROJECT" -f "$COMPOSE" run --rm -T --no-deps \
  -e GMF_LIVE_PLUGIN_ENDPOINT=notification-plugin:9443 \
  -e GMF_LIVE_PLUGIN_NAME=telegram-notification-sink \
  -e GMF_LIVE_PLUGIN_TOKEN=dev-plugin-token \
  test-runner sh -eu -c '
signed_email_tests=$(go test -list "^TestSignedEmailBackend" ./internal/notifyruntime)
printf "%s\n" "$signed_email_tests" | grep -qx "TestSignedEmailBackendSendsOnlyOpenPGPMIMESignedAlert"
printf "%s\n" "$signed_email_tests" | grep -qx "TestSignedEmailBackendFailsClosedWithoutSignerOrMatchingIdentity"
runtime_email_tests=$(go test -list "^TestSignedEmailNotificationSinkGRPC" ./cmd/gmf-plugin)
printf "%s\n" "$runtime_email_tests" | grep -qx "TestSignedEmailNotificationSinkGRPCDeliversCryptographicallyVerifiedSMTPAndRejectsPrompt"
go test -v -count=1 ./cmd/gmf-plugin ./internal/plugin ./internal/notification ./internal/notifyruntime -run "^(TestLivePluginControlOverGRPC|TestLiveNotificationBackendOverGRPC|TestRuntimeCommandProvider|TestTelegramReceiver|TestApprovalExecutor|TestSignedEmailBackend.*|TestSignedEmailNotificationSinkGRPC.*)$"
'
$DOCKER compose -p "$PROJECT" -f "$COMPOSE" down -v --remove-orphans
trap - EXIT HUP INT TERM
echo "containerized notification plugin gRPC/backend smoke passed"
