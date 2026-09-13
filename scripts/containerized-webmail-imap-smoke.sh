#!/bin/sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
COMPOSE="$ROOT/compose/reference/docker-compose.yml"
PROJECT=${GOTTH_MAIL_WEBMAIL_IMAP_SMOKE_PROJECT:-gotth-mail-webmail-imap-smoke}
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
    $DOCKER compose -p "$PROJECT" -f "$COMPOSE" logs --no-color --tail=160 gotth-mail postfix dovecot rspamd >&2 || true
  fi
  $DOCKER compose -p "$PROJECT" -f "$COMPOSE" down -v --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT
$DOCKER compose -p "$PROJECT" -f "$COMPOSE" down -v --remove-orphans >/dev/null 2>&1 || true
$DOCKER compose -p "$PROJECT" -f "$COMPOSE" up -d --build gotth-mail postfix dovecot rspamd
wait_tcp() {
  host=$1
  port=$2
  for i in $(seq 1 90); do
    if $DOCKER compose -p "$PROJECT" -f "$COMPOSE" exec -T postfix sh -lc "nc -z $host $port" >/dev/null 2>&1; then return 0; fi
    [ "$i" = 90 ] && { echo "timeout waiting for $host:$port" >&2; return 1; }
    sleep 1
  done
}
wait_tcp postfix 25
wait_tcp dovecot 143
wait_tcp rspamd 11332
subject="GOTTH Mail webmail IMAP smoke $(date +%s)"
$DOCKER compose -p "$PROJECT" -f "$COMPOSE" build test-runner
$DOCKER compose -p "$PROJECT" -f "$COMPOSE" run --rm -T --no-deps \
  -e GOTTH_MAIL_LIVE_SMTP_ADDR=postfix:25 \
  -e "GOTTH_MAIL_LIVE_SMTP_SUBJECT=$subject" \
  test-runner go test -count=1 ./internal/webmail -run TestNetSMTPSubmitterLiveComposePostfix
for i in $(seq 1 60); do
  count=$($DOCKER compose -p "$PROJECT" -f "$COMPOSE" exec -T postfix sh -lc 'find /mail/example.test/smoke/new -type f 2>/dev/null | wc -l')
  [ "$count" -gt 0 ] && break
  [ "$i" = 60 ] && { echo "message was not delivered before IMAP smoke" >&2; exit 1; }
  sleep 1
done
$DOCKER compose -p "$PROJECT" -f "$COMPOSE" run --rm -T --no-deps \
  -e GOTTH_MAIL_LIVE_IMAP_ADDR=dovecot:143 \
  -e GOTTH_MAIL_LIVE_IMAP_USER=smoke@example.test \
  -e GOTTH_MAIL_LIVE_IMAP_PASSWORD=smoke-secret \
  -e "GOTTH_MAIL_LIVE_IMAP_SUBJECT=$subject" \
  test-runner go test -count=1 ./internal/webmail -run TestNetIMAPClientLiveComposeDovecot
echo "containerized webmail IMAP smoke passed"
