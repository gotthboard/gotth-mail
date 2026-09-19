#!/bin/sh
set -eu

repo_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
compose_file="$repo_dir/compose/reference/docker-compose.yml"
project="gotth-mail-outbound-policy-${USER:-test}-$$"
docker_command=${DOCKER:-docker}
if ! $docker_command info >/dev/null 2>&1; then
  docker_command="sudo docker"
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

external_response=$(compose exec -T postfix sh -c "printf 'request=smtpd_access_policy\nprotocol_state=RCPT\ninstance=smoke-1\nsasl_username=smoke@example.test\nsender=smoke@example.test\nrecipient=outside@example.net\n\n' | nc gotth-mail 10025")
printf '%s\n' "$external_response" | grep -q '^action=550 5.7.1 '

same_domain_response=$(compose exec -T postfix sh -c "printf 'request=smtpd_access_policy\nprotocol_state=RCPT\ninstance=smoke-2\nsasl_username=smoke@example.test\nsender=smoke@example.test\nrecipient=postmaster@example.test\n\n' | nc gotth-mail 10025")
printf '%s\n' "$same_domain_response" | grep -qx 'action=DUNNO'

compose exec -T postfix sh -c "printf 'From: smoke@example.test\nTo: outside@example.net\nSubject: outbound policy hold smoke\n\npolicy smoke\n' | /usr/sbin/sendmail -f smoke@example.test outside@example.net"

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

printf 'containerized outbound policy smoke passed; queue %s held and rechecked\n' "$queue_id"
