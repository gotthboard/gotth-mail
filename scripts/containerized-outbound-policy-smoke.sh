#!/bin/sh
set -eu

repo_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
compose_file="$repo_dir/compose/reference/docker-compose.yml"
project="gotth-mail-outbound-policy-${USER:-test}-$$"
docker_command=${DOCKER:-docker}
: "${GOTTH_MAIL_NOTIFICATION_EMAIL_FROM:=alerts@example.test}"
: "${GOTTH_MAIL_SYSTEM_SENDER_SMTP_USERNAME:=system:alerts@example.test}"
: "${GOTTH_MAIL_SYSTEM_SENDER_SMTP_PASSWORD:=reference-system-sender-smtp-secret}"
export GOTTH_MAIL_NOTIFICATION_EMAIL_FROM GOTTH_MAIL_SYSTEM_SENDER_SMTP_USERNAME GOTTH_MAIL_SYSTEM_SENDER_SMTP_PASSWORD
if ! $docker_command info >/dev/null 2>&1; then
  docker_command="sudo --preserve-env=GOTTH_MAIL_NOTIFICATION_EMAIL_FROM,GOTTH_MAIL_SYSTEM_SENDER_SMTP_USERNAME,GOTTH_MAIL_SYSTEM_SENDER_SMTP_PASSWORD docker"
fi
compose() {
  $docker_command compose -p "$project" -f "$compose_file" "$@"
}
cleanup() {
  compose down -v --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

compose up -d --build database gotth-mail rspamd postfix

attempt=0
until compose exec -T gotth-mail wget -qO- http://127.0.0.1:8080/healthz >/dev/null 2>&1; do
  attempt=$((attempt + 1))
  if [ "$attempt" -ge 90 ]; then
    compose logs gotth-mail postfix
    exit 1
  fi
  sleep 1
done

attempt=0
until compose exec -T postfix nc -z rspamd 11332 >/dev/null 2>&1; do
  attempt=$((attempt + 1))
  if [ "$attempt" -ge 60 ]; then
    compose logs rspamd postfix
    exit 1
  fi
  sleep 1
done

compose exec -T postfix postconf -h enable_long_queue_ids | grep -qx yes
compose exec -T postfix postconf -h default_transport | grep -qx 'gotth_policy:'
compose exec -T postfix postmap -q '<>' lmdb:/etc/postfix/sender_default_transports | grep -qx 'gotth_automatic:'
compose exec -T postfix postconf -M gotth_automatic/unix | grep -q -- '--system-sender-id=system:mailer-daemon@example.test'
if compose exec -T postfix postconf -h import_environment | grep -q 'GOTTH_MAIL_POSTFIX_RELEASE_TOKEN'; then
  echo 'release credential leaked into Postfix import_environment' >&2
  exit 1
fi
if compose exec -T postfix postconf -h export_environment | grep -q 'GOTTH_MAIL_POSTFIX_RELEASE_TOKEN'; then
  echo 'release credential leaked into Postfix export_environment' >&2
  exit 1
fi

external_response=$(compose exec -T postfix sh -c "printf 'request=smtpd_access_policy\nprotocol_state=RCPT\ninstance=smoke-1\nsasl_username=smoke@example.test\nsender=smoke@example.test\nrecipient=outside@example.net\n\n' | nc gotth-mail 10025")
printf '%s\n' "$external_response" | grep -q '^action=550 5.7.1 '

same_domain_response=$(compose exec -T postfix sh -c "printf 'request=smtpd_access_policy\nprotocol_state=RCPT\ninstance=smoke-2\nsasl_username=smoke@example.test\nsender=smoke@example.test\nrecipient=postmaster@example.test\n\n' | nc gotth-mail 10025")
printf '%s\n' "$same_domain_response" | grep -qx 'action=DUNNO'

system_external_response=$(compose exec -T postfix sh -c "printf 'request=smtpd_access_policy\nprotocol_state=RCPT\ninstance=smoke-system-1\nsasl_username=system:alerts@example.test\nsender=alerts@example.test\nrecipient=outside@example.net\n\n' | nc gotth-mail 10025")
printf '%s\n' "$system_external_response" | grep -q '^action=550 5.7.1 '

compose exec -T postfix sh -c "printf 'From: sender@remote.test\nTo: forward@example.test\nSubject: inbound forward policy hold smoke\n\npolicy smoke\n' | /usr/sbin/sendmail -f sender@remote.test forward@example.test"

attempt=0
queue_id=""
while [ -z "$queue_id" ]; do
  queue_id=$(compose exec -T postfix postqueue -j | jq -r 'select(.queue_name == "hold") | .queue_id' | head -n 1)
  attempt=$((attempt + 1))
  if [ "$attempt" -ge 60 ]; then
    compose logs gotth-mail postfix
    compose exec -T postfix postqueue -p || true
    exit 1
  fi
  sleep 1
done

hold_state=$(compose exec -T database psql -U gotth_mail -d gotth_mail -Atc "SELECT hold_state FROM outbound_queue_messages WHERE queue_id='$queue_id'")
test "$hold_state" = "held"

compose exec -T gotth-mail wget -qO- \
  --header='Content-Type: application/json' \
  --header='Authorization: Bearer reference-postfix-helper-token-32bytes' \
  --header='X-Correlation-ID: outbound-policy-smoke-reconcile' \
  --post-data="{\"queue_id\":\"$queue_id\"}" \
  http://127.0.0.1:8080/internal/v1/postfix/queue/reconcile \
  | jq -e '.decision == "ok" and .reason == "outbound_queue_hold_already_applied"' >/dev/null

compose exec -T database psql -U gotth_mail -d gotth_mail -Atc "SELECT count(*) FROM audit_events WHERE resource_type='postfix_queue' AND resource_id='$queue_id' AND action='queue.policy_hold.applied' AND result='success'" | grep -qx 1

if compose exec -T gotth-mail wget -qO- \
  --header='Content-Type: application/json' \
  --header='Authorization: Bearer reference-postfix-helper-token-32bytes' \
  --post-data="{\"queue_id\":\"$queue_id\"}" \
  http://127.0.0.1:8080/internal/v1/postfix/queue/release-preview >/dev/null 2>&1; then
  echo 'delivery helper credential was accepted by release preview' >&2
  exit 1
fi

compose exec -T database psql -U gotth_mail -d gotth_mail -v ON_ERROR_STOP=1 -c \
  "UPDATE domains SET outbound_scope='unrestricted',outbound_policy_revision=outbound_policy_revision+1,updated_at=CURRENT_TIMESTAMP WHERE name='example.test'" >/dev/null

preview=$(compose exec -T gotth-mail wget -qO- \
  --header='Content-Type: application/json' \
  --header='Authorization: Bearer reference-postfix-release-token-32byte' \
  --header='X-Correlation-ID: outbound-policy-smoke-release-preview' \
  --post-data="{\"queue_id\":\"$queue_id\"}" \
  http://127.0.0.1:8080/internal/v1/postfix/queue/release-preview)
printf '%s\n' "$preview" | jq -e --arg queue_id "$queue_id" \
  '.decision == "ok" and .reason == "outbound_queue_release_previewed" and .queue_id == $queue_id and .queue_state == "held" and (.confirmation | test("^[0-9a-f]{64}$"))' >/dev/null
confirmation=$(printf '%s\n' "$preview" | jq -r '.confirmation')

compose exec -T gotth-mail wget -qO- \
  --header='Content-Type: application/json' \
  --header='Authorization: Bearer reference-postfix-release-token-32byte' \
  --header='X-Correlation-ID: outbound-policy-smoke-release' \
  --post-data="{\"queue_id\":\"$queue_id\",\"confirmation\":\"$confirmation\"}" \
  http://127.0.0.1:8080/internal/v1/postfix/queue/release \
  | jq -e --arg queue_id "$queue_id" '.decision == "ok" and .reason == "outbound_queue_released" and .queue_id == $queue_id and .queue_state == "released"' >/dev/null

release_state=$(compose exec -T database psql -U gotth_mail -d gotth_mail -Atc "SELECT hold_state FROM outbound_queue_messages WHERE queue_id='$queue_id'")
test "$release_state" = "released"
if compose exec -T postfix postqueue -j | jq -e --arg queue_id "$queue_id" 'select(.queue_id == $queue_id and .queue_name == "hold")' >/dev/null; then
  echo 'released queue message remained in the Postfix hold queue' >&2
  exit 1
fi
compose exec -T database psql -U gotth_mail -d gotth_mail -Atc "SELECT count(*) FROM audit_events WHERE resource_type='postfix_queue' AND resource_id='$queue_id' AND action='queue.policy_hold.release_start' AND result='success'" | grep -qx 1
compose exec -T database psql -U gotth_mail -d gotth_mail -Atc "SELECT count(*) FROM audit_events WHERE resource_type='postfix_queue' AND resource_id='$queue_id' AND action='queue.policy_hold.released' AND result='success'" | grep -qx 1

compose exec -T postfix sh -c "rm -f /tmp/gotth-mail-outbound-sink.accepted; socat TCP-LISTEN:9,bind=127.0.0.1,reuseaddr,fork EXEC:'sh /reference/postfix/smtp-sink.sh' >/tmp/gotth-mail-outbound-sink.log 2>&1 &"
compose exec -T postfix postqueue -f
attempt=0
until compose exec -T postfix test -f /tmp/gotth-mail-outbound-sink.accepted; do
  attempt=$((attempt + 1))
  if [ "$attempt" -ge 60 ]; then
    compose logs gotth-mail postfix
    compose exec -T postfix cat /tmp/gotth-mail-outbound-sink.log || true
    compose exec -T postfix postqueue -j || true
    exit 1
  fi
  sleep 1
done

# One whole-message pipe invocation must yield one relay transaction carrying
# both recipients. A per-recipient pipe split would append two one-recipient
# acceptances and expose duplicate whole-message relay behavior.
sleep 2
if ! compose exec -T postfix sh -c "test \"\$(wc -l < /tmp/gotth-mail-outbound-sink.accepted)\" -eq 1 && grep -qx 2 /tmp/gotth-mail-outbound-sink.accepted"; then
  echo 'unexpected outbound SMTP transaction or recipient count' >&2
  compose exec -T postfix cat /tmp/gotth-mail-outbound-sink.accepted >&2 || true
  compose exec -T postfix cat /tmp/gotth-mail-outbound-sink.log >&2 || true
  compose logs gotth-mail postfix >&2 || true
  exit 1
fi

compose exec -T postfix rm -f /tmp/gotth-mail-outbound-sink.accepted
GOTTH_MAIL_LIVE_SMTP_ADDR=127.0.0.1:2525 \
GOTTH_MAIL_LIVE_SMTP_FROM=alerts@example.test \
GOTTH_MAIL_LIVE_SMTP_TO=outside@example.net \
GOTTH_MAIL_LIVE_SMTP_USERNAME="$GOTTH_MAIL_SYSTEM_SENDER_SMTP_USERNAME" \
GOTTH_MAIL_LIVE_SMTP_PASSWORD="$GOTTH_MAIL_SYSTEM_SENDER_SMTP_PASSWORD" \
  go test ./internal/webmail -run '^TestNetSMTPSubmitterLiveComposePostfix$' -count=1
attempt=0
until compose exec -T postfix test -f /tmp/gotth-mail-outbound-sink.accepted; do
  attempt=$((attempt + 1))
  if [ "$attempt" -ge 60 ]; then
    compose logs gotth-mail postfix
    compose exec -T postfix cat /tmp/gotth-mail-outbound-sink.log || true
    exit 1
  fi
  sleep 1
done
compose exec -T postfix sh -c "test \"\$(wc -l < /tmp/gotth-mail-outbound-sink.accepted)\" -eq 1 && grep -qx 1 /tmp/gotth-mail-outbound-sink.accepted"
compose exec -T database psql -U gotth_mail -d gotth_mail -Atc "SELECT count(*) FROM outbound_queue_sources WHERE source_kind='system_sender' AND object_id='system:alerts@example.test'" | grep -qx 1

compose exec -T postfix rm -f /tmp/gotth-mail-outbound-sink.accepted
compose exec -T postfix sh -c "printf 'From: Mailer Daemon <mailer-daemon@example.test>\nTo: outside@example.net\nSubject: automatic DSN transport smoke\n\nautomatic policy smoke\n' | /usr/sbin/sendmail -f '<>' outside@example.net"
attempt=0
until compose exec -T postfix test -f /tmp/gotth-mail-outbound-sink.accepted; do
  attempt=$((attempt + 1))
  if [ "$attempt" -ge 20 ]; then
    compose logs gotth-mail postfix
    compose exec -T postfix cat /tmp/gotth-mail-outbound-sink.log || true
    compose exec -T postfix postqueue -j || true
    exit 1
  fi
  sleep 1
done
compose exec -T postfix sh -c "test \"\$(wc -l < /tmp/gotth-mail-outbound-sink.accepted)\" -eq 1 && grep -qx 1 /tmp/gotth-mail-outbound-sink.accepted"
compose exec -T database psql -U gotth_mail -d gotth_mail -Atc "SELECT count(*) FROM outbound_queue_sources WHERE source_kind='system_sender' AND object_id='system:mailer-daemon@example.test'" | grep -qx 1

printf 'containerized outbound policy smoke passed; inbound forward queue %s held, rechecked, explicitly released, one unrestricted two-recipient relay accepted, one authenticated system-sender relay admitted at submission and final transport, and one null-sender automatic relay bound to durable mailer-daemon authority\n' "$queue_id"
