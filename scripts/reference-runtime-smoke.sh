#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
COMPOSE="$ROOT/compose/reference/docker-compose.yml"
PROJECT=${GMF_SMOKE_PROJECT:-gmf-v1-smoke}
DOCKER=${DOCKER:-docker}
if ! $DOCKER info >/dev/null 2>&1; then
  DOCKER="sudo docker"
fi

cleanup() {
  rc=$?
  if [ "$rc" -ne 0 ]; then
    $DOCKER compose -p "$PROJECT" -f "$COMPOSE" ps >&2 || true
    $DOCKER compose -p "$PROJECT" -f "$COMPOSE" logs --no-color --tail=160 gophermailforge postfix dovecot rspamd >&2 || true
  fi
  $DOCKER compose -p "$PROJECT" -f "$COMPOSE" down -v --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT

cleanup

$DOCKER compose -p "$PROJECT" -f "$COMPOSE" up -d --build gophermailforge postfix dovecot rspamd webmail external-webmail-plugin manual-dns-plugin cert-plugin backup-plugin

wait_http() {
  local url=$1
  for _ in $(seq 1 90); do
    if curl -fsS "$url" >/dev/null 2>&1; then return 0; fi
    sleep 1
  done
  echo "timeout waiting for $url" >&2
  return 1
}
wait_tcp() {
  local host=$1 port=$2
  for _ in $(seq 1 90); do
    if $DOCKER compose -p "$PROJECT" -f "$COMPOSE" exec -T postfix sh -lc "nc -z $host $port" >/dev/null 2>&1; then return 0; fi
    sleep 1
  done
  echo "timeout waiting for $host:$port" >&2
  return 1
}

wait_http http://127.0.0.1:8080/healthz
wait_tcp postfix 25
wait_tcp dovecot 143
wait_tcp rspamd 11332
wait_tcp rspamd 11333
wait_tcp webmail 8080

curl -fsS -H 'X-Correlation-ID: smoke' http://127.0.0.1:8080/internal/v1/postfix/recipients/smoke@example.test | grep '"decision":"ok"' >/dev/null
curl -fsS -H 'X-Correlation-ID: smoke' http://127.0.0.1:8080/internal/v1/rspamd/dkim/example.test | grep '"decision":"ok"' >/dev/null

$DOCKER compose -p "$PROJECT" -f "$COMPOSE" exec -T postfix sh -lc '(
  sleep 1
  printf "EHLO smoke.example.test\r\n"
  sleep 1
  printf "MAIL FROM:<smoke@example.test>\r\n"
  sleep 1
  printf "RCPT TO:<nobody@example.test>\r\n"
  sleep 1
  printf "QUIT\r\n"
) | nc 127.0.0.1 25 | tee /tmp/smtp-reject.out
grep -E "recipient unknown|Recipient address rejected|550|554" /tmp/smtp-reject.out >/dev/null'

$DOCKER compose -p "$PROJECT" -f "$COMPOSE" exec -T dovecot sh -lc 'grep "SHA512-CRYPT" /etc/dovecot/passwd >/dev/null'

before=$($DOCKER compose -p "$PROJECT" -f "$COMPOSE" exec -T postfix sh -lc 'find /mail/example.test/smoke/new -type f 2>/dev/null | wc -l')

$DOCKER compose -p "$PROJECT" -f "$COMPOSE" exec -T postfix sh -lc '(
  sleep 1
  printf "EHLO smoke.example.test\r\n"
  sleep 1
  printf "MAIL FROM:<smoke@example.test>\r\n"
  sleep 1
  printf "RCPT TO:<alias@example.test>\r\n"
  sleep 1
  printf "DATA\r\n"
  sleep 1
  printf "Subject: GopherMailForge smoke\r\n"
  printf "From: smoke@example.test\r\n"
  printf "To: alias@example.test\r\n"
  printf "\r\n"
  printf "smoke-body-20260716\r\n"
  printf ".\r\n"
  sleep 1
  printf "QUIT\r\n"
) | nc 127.0.0.1 25 | tee /tmp/smtp.out
grep -E "250 2.0.0|250 Ok|queued as" /tmp/smtp.out >/dev/null'

for _ in $(seq 1 60); do
  after=$($DOCKER compose -p "$PROJECT" -f "$COMPOSE" exec -T postfix sh -lc 'find /mail/example.test/smoke/new -type f 2>/dev/null | wc -l')
  if [ "$after" -gt "$before" ]; then break; fi
  sleep 1
done
if [ "${after:-0}" -le "$before" ]; then
  echo "message was not delivered to smoke Maildir" >&2
  $DOCKER compose -p "$PROJECT" -f "$COMPOSE" logs --no-color postfix >&2 || true
  exit 1
fi

$DOCKER compose -p "$PROJECT" -f "$COMPOSE" exec -T dovecot sh -lc '(
  sleep 1
  printf "a login smoke@example.test smoke-secret\r\n"
  sleep 1
  printf "b select INBOX\r\n"
  sleep 1
  printf "c fetch 1 body[header.fields (subject)]\r\n"
  sleep 1
  printf "d logout\r\n"
) | nc 127.0.0.1 143 | tee /tmp/imap.out
grep "a OK" /tmp/imap.out >/dev/null
grep "GopherMailForge smoke" /tmp/imap.out >/dev/null'

msg_path=$($DOCKER compose -p "$PROJECT" -f "$COMPOSE" exec -T postfix sh -lc 'find /mail/example.test/smoke -type f | head -1')
msg_rel=${msg_path#/mail/}
curl -fsS --path-as-is "http://127.0.0.1:8081/$msg_rel" | tee /tmp/gmf-smoke-message.out | grep 'smoke-body-20260716' >/dev/null
grep '^DKIM-Signature:' /tmp/gmf-smoke-message.out >/dev/null

$DOCKER compose -p "$PROJECT" -f "$COMPOSE" exec -T rspamd sh -lc 'test -s /run/rspamd/dkim/example.test.mail.key && test -s /run/rspamd/dkim/example.test.mail.txt && rspamadm configtest >/tmp/rspamd-configtest.out && grep -i "syntax OK" /tmp/rspamd-configtest.out >/dev/null'
$DOCKER compose -p "$PROJECT" -f "$COMPOSE" logs --no-color gophermailforge | grep 'postfix policy recipient=alias@example.test decision=ok' >/dev/null
$DOCKER compose -p "$PROJECT" -f "$COMPOSE" logs --no-color gophermailforge | grep 'postfix policy recipient=nobody@example.test decision=not_found' >/dev/null

cat <<'OK'
reference runtime smoke passed:
- GopherMailForge daemon contracts reachable
- real Postfix queried the GopherMailForge policy socket, rejected an unknown recipient, accepted SMTP, and delivered alias mail to Maildir
- real Dovecot used generated GopherMailForge-derived auth/userdb material and IMAP login/read succeeded
- webmail provider exposed delivered Maildir message
- real Rspamd ran in the Postfix milter path, DKIM-signed the delivered message, and validated config
OK
