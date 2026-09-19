#!/bin/sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
COMPOSE="$ROOT/compose/reference/docker-compose.yml"
PROJECT=${GOTTH_MAIL_NOTIFICATION_PLUGIN_SMOKE_PROJECT:-gotth-mail-notification-plugin-smoke-$(date +%s)-$$}
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
    $DOCKER compose -p "$PROJECT" -f "$COMPOSE" logs --no-color --tail=160 notification-plugin gotth-mail postfix database >&2 || true
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
DOCKER="$DOCKER" "$ROOT/scripts/verify-notification-compose.sh"
$DOCKER compose -p "$PROJECT" -f "$COMPOSE" up -d --build notification-plugin
$DOCKER compose -p "$PROJECT" -f "$COMPOSE" build test-runner
for i in $(seq 1 90); do
  if $DOCKER compose -p "$PROJECT" -f "$COMPOSE" run --rm -T --no-deps test-runner sh -lc 'test -S /run/gotth-mail-plugins/telegram.sock' >/dev/null 2>&1; then break; fi
  [ "$i" = 90 ] && { echo "timeout waiting for notification plugin Unix socket" >&2; exit 1; }
  sleep 1
done
$DOCKER compose -p "$PROJECT" -f "$COMPOSE" run --rm -T --no-deps \
  -e GOTTH_MAIL_LIVE_PLUGIN_ENDPOINT=unix:///run/gotth-mail-plugins/telegram.sock \
  -e GOTTH_MAIL_LIVE_PLUGIN_NAME=telegram-notification-sink \
  -e GOTTH_MAIL_LIVE_PLUGIN_TOKEN=dev-plugin-token \
  test-runner sh -eu -c '
signed_email_tests=$(go test -list "^TestSignedEmailBackend" ./internal/notifyruntime)
printf "%s\n" "$signed_email_tests" | grep -qx "TestSignedEmailBackendSendsOnlyOpenPGPMIMESignedAlert"
printf "%s\n" "$signed_email_tests" | grep -qx "TestSignedEmailBackendFailsClosedWithoutSignerOrMatchingIdentity"
runtime_email_tests=$(go test -list "^TestSignedEmailNotificationSinkGRPC" ./cmd/gotth-mail-plugin)
printf "%s\n" "$runtime_email_tests" | grep -qx "TestSignedEmailNotificationSinkGRPCDeliversCryptographicallyVerifiedSMTPAndRejectsPrompt"
go test -v -count=1 ./cmd/gotth-mail-plugin ./internal/plugin ./internal/notification ./internal/notifyruntime -run "^(TestLivePluginControlOverGRPC|TestLiveNotificationBackendOverGRPC|TestRuntimeCommandProvider|TestTelegramReceiver|TestApprovalExecutor|TestSignedEmailBackend.*|TestSignedEmailNotificationSinkGRPC.*)$"
'
$DOCKER compose -p "$PROJECT" -f "$COMPOSE" down -v --remove-orphans

# Full production path: authenticated initiation -> captured Telegram prompt
# -> callback -> SQL lease -> real Postfix flush -> durable completion audit.
# The reference-only failpoint returns after the first successful flush to
# reproduce the ambiguous helper-success/SQL-completion crash window.
$DOCKER compose --env-file "$ROOT/compose/reference/notification-smoke.env" \
  -p "$PROJECT" -f "$COMPOSE" up -d --build postfix
for i in $(seq 1 120); do
  if $DOCKER compose -p "$PROJECT" -f "$COMPOSE" exec -T postfix sh -c \
    'curl -fsS http://gotth-mail:8080/healthz >/dev/null && postfix status >/dev/null 2>&1 && nc -z rspamd 11332'; then break; fi
  [ "$i" = 120 ] && { echo "timeout waiting for full notification approval stack" >&2; exit 1; }
  sleep 1
done
$DOCKER compose -p "$PROJECT" -f "$COMPOSE" exec -T database psql -U gotth_mail -d gotth_mail -v ON_ERROR_STOP=1 -c \
  "UPDATE domains SET outbound_scope='unrestricted',outbound_policy_revision=outbound_policy_revision+1,updated_at=CURRENT_TIMESTAMP WHERE name='example.test'" >/dev/null
$DOCKER compose -p "$PROJECT" -f "$COMPOSE" exec -T postfix sh -c \
  "printf 'From: Mailer Daemon <mailer-daemon@example.test>\nTo: outside@example.net\nSubject: notification approval smoke\n\nreal Postfix approval path\n' | /usr/sbin/sendmail -f '<>' outside@example.net"
queue_id=""
for i in $(seq 1 60); do
  queue_id=$($DOCKER compose -p "$PROJECT" -f "$COMPOSE" exec -T postfix postqueue -j | jq -r 'select(.queue_name == "deferred") | .queue_id' | head -n1)
  [ -n "$queue_id" ] && break
  [ "$i" = 60 ] && { echo "timeout waiting for deferred Postfix message" >&2; exit 1; }
  sleep 1
done
approval=$($DOCKER compose -p "$PROJECT" -f "$COMPOSE" exec -T postfix curl -fsS \
  -H 'Authorization: Bearer reference-notification-admin-secret' \
  -H 'X-Correlation-ID: notification-approval-container-smoke' \
  -H 'Content-Type: application/json' \
  -d '{"external_actor_id":"chat:42:user:99"}' \
  http://gotth-mail:8080/api/v1/queue/flush)
approval_id=$(printf '%s\n' "$approval" | jq -er '.approval_id')
prompt=""
for i in $(seq 1 30); do
  prompt=$($DOCKER compose -p "$PROJECT" -f "$COMPOSE" exec -T notification-plugin sh -c 'test -s /run/gotth-mail-plugins/prompts.jsonl && tail -n1 /run/gotth-mail-plugins/prompts.jsonl' 2>/dev/null || true)
  [ -n "$prompt" ] && break
  [ "$i" = 30 ] && { echo "timeout waiting for captured approval prompt" >&2; exit 1; }
  sleep 1
done
test "$(printf '%s\n' "$prompt" | jq -r '.ID')" = "$approval_id"
confirmation=$(printf '%s\n' "$prompt" | jq -er '.ConfirmationToken')
$DOCKER compose -p "$PROJECT" -f "$COMPOSE" exec -T postfix sh -c \
  "rm -f /tmp/gotth-mail-outbound-sink.accepted; socat TCP-LISTEN:9,bind=127.0.0.1,reuseaddr,fork EXEC:'sh /reference/postfix/smtp-sink.sh' >/tmp/gotth-mail-outbound-sink.log 2>&1 &"
callback_data="gm:a:$approval_id:$confirmation"
callback=$(jq -nc --arg data "$callback_data" '{update_id:9001,callback_query:{id:"approval-smoke-1",from:{id:99},message:{message_id:7,from:{id:99},chat:{id:42},text:"approval"},data:$data}}')
first_reply=$($DOCKER compose -p "$PROJECT" -f "$COMPOSE" exec -T postfix curl -fsS \
  -H 'X-Telegram-Bot-Api-Secret-Token: reference-telegram-webhook-secret' \
  -H 'Content-Type: application/json' -d "$callback" \
  http://gotth-mail:8080/internal/v1/notifications/telegram)
if ! printf '%s\n' "$first_reply" | jq -e '.text == "approval rejected"' >/dev/null; then
  echo "ambiguous approval callback was not rejected: $first_reply" >&2
  exit 1
fi
for i in $(seq 1 60); do
  if $DOCKER compose -p "$PROJECT" -f "$COMPOSE" exec -T postfix test -f /tmp/gotth-mail-outbound-sink.accepted; then break; fi
  [ "$i" = 60 ] && { echo "approved real Postfix flush did not reach SMTP sink" >&2; exit 1; }
  sleep 1
done
if $DOCKER compose -p "$PROJECT" -f "$COMPOSE" exec -T postfix postqueue -j | jq -e --arg id "$queue_id" 'select(.queue_id == $id)' >/dev/null; then
  echo "approved Postfix queue message remained queued" >&2
  exit 1
fi
approval_state=$($DOCKER compose -p "$PROJECT" -f "$COMPOSE" exec -T database psql -U gotth_mail -d gotth_mail -Atc \
  "SELECT result FROM notification_approvals WHERE id='$approval_id'")
if [ "$approval_state" != executing ]; then
  echo "ambiguous approval did not retain executing lease: $approval_state" >&2
  exit 1
fi
sleep 3
callback=$(jq -nc --arg data "$callback_data" '{update_id:9002,callback_query:{id:"approval-smoke-2",from:{id:99},message:{message_id:8,from:{id:99},chat:{id:42},text:"approval"},data:$data}}')
second_reply=$($DOCKER compose -p "$PROJECT" -f "$COMPOSE" exec -T postfix curl -fsS \
  -H 'X-Telegram-Bot-Api-Secret-Token: reference-telegram-webhook-secret' \
  -H 'Content-Type: application/json' -d "$callback" \
  http://gotth-mail:8080/internal/v1/notifications/telegram)
if ! printf '%s\n' "$second_reply" | jq -e '.text == "approval accepted"' >/dev/null; then
  echo "stale approval recovery was not accepted: $second_reply" >&2
  exit 1
fi
approval_state=$($DOCKER compose -p "$PROJECT" -f "$COMPOSE" exec -T database psql -U gotth_mail -d gotth_mail -Atc \
  "SELECT result || ':' || execution_attempts FROM notification_approvals WHERE id='$approval_id'")
if [ "$approval_state" != approved:2 ]; then
  echo "recovered approval has wrong durable state: $approval_state" >&2
  exit 1
fi
callback=$(jq -nc --arg data "$callback_data" '{update_id:9003,callback_query:{id:"approval-smoke-3",from:{id:99},message:{message_id:9,from:{id:99},chat:{id:42},text:"approval"},data:$data}}')
third_reply=$($DOCKER compose -p "$PROJECT" -f "$COMPOSE" exec -T postfix curl -fsS \
  -H 'X-Telegram-Bot-Api-Secret-Token: reference-telegram-webhook-secret' \
  -H 'Content-Type: application/json' -d "$callback" \
  http://gotth-mail:8080/internal/v1/notifications/telegram)
if ! printf '%s\n' "$third_reply" | jq -e '.text == "approval rejected"' >/dev/null; then
  echo "completed approval replay was not rejected: $third_reply" >&2
  exit 1
fi
confirm_audits=$($DOCKER compose -p "$PROJECT" -f "$COMPOSE" exec -T database psql -U gotth_mail -d gotth_mail -Atc \
  "SELECT count(*) FROM audit_events WHERE correlation_id='notification-approval-container-smoke' AND action='notification.approval.confirm' AND result='success'")
execute_audits=$($DOCKER compose -p "$PROJECT" -f "$COMPOSE" exec -T database psql -U gotth_mail -d gotth_mail -Atc \
  "SELECT count(*) FROM audit_events WHERE correlation_id='notification-approval-container-smoke' AND action='notification.approval.execute' AND result='success'")
if [ "$confirm_audits:$execute_audits" != 2:1 ]; then
  echo "approval audit cardinality mismatch: confirm=$confirm_audits execute=$execute_audits" >&2
  exit 1
fi
$DOCKER compose -p "$PROJECT" -f "$COMPOSE" down -v --remove-orphans
trap - EXIT HUP INT TERM
echo "real Postfix approval and ambiguous-recovery smoke passed"
echo "containerized notification plugin gRPC/backend smoke passed"
