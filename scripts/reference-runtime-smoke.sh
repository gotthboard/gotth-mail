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
wait_tcp webmail 80

curl -fsS -H 'X-Correlation-ID: smoke' http://127.0.0.1:8080/internal/v1/postfix/recipients/smoke@example.test | grep '"decision":"ok"' >/dev/null
curl -fsS -H 'X-Correlation-ID: smoke' http://127.0.0.1:8080/internal/v1/rspamd/dkim/example.test | grep '"decision":"ok"' >/dev/null
curl -fsS -H 'X-Correlation-ID: smoke' -H 'X-GMF-Plugin-Token: dev-plugin-token' http://127.0.0.1:8080/api/v1/doctor -o /tmp/gmf-doctor.json
grep 'acme_not_configured_reference_manual_mode' /tmp/gmf-doctor.json >/dev/null
grep '"category":"plugin"' /tmp/gmf-doctor.json >/dev/null

python3 - <<'PYSMTPREJECT'
import smtplib
import sys

with smtplib.SMTP("127.0.0.1", 2525, timeout=30) as smtp:
    smtp.set_debuglevel(1)
    smtp.ehlo("smoke.example.test")
    smtp.mail("smoke@example.test")
    code, message = smtp.rcpt("nobody@example.test")  # RCPT TO:<nobody@example.test>
    text = message.decode("utf-8", "replace") if isinstance(message, bytes) else str(message)
    print(f"reject rcpt code={code} message={text}")
    if code < 500 or not any(marker in text.lower() for marker in ("recipient unknown", "recipient address rejected", "not found")):
        sys.exit("expected unknown-recipient rejection")
PYSMTPREJECT

$DOCKER compose -p "$PROJECT" -f "$COMPOSE" exec -T dovecot sh -lc 'grep "SHA512-CRYPT" /etc/dovecot/passwd >/dev/null'

before=$($DOCKER compose -p "$PROJECT" -f "$COMPOSE" exec -T postfix sh -lc 'find /mail/example.test/smoke/new -type f 2>/dev/null | wc -l')

python3 - <<'PYSMTPDELIVER'
from email.message import EmailMessage
import smtplib

message = EmailMessage()
message["Subject"] = "GopherMailForge smoke"
message["From"] = "smoke@example.test"
message["To"] = "alias@example.test"  # RCPT TO:<alias@example.test>
message.set_content("smoke-body-20260716")

with smtplib.SMTP("127.0.0.1", 2525, timeout=30) as smtp:
    smtp.set_debuglevel(1)
    smtp.ehlo("smoke.example.test")
    refused = smtp.send_message(message)
    if refused:
        raise SystemExit(f"unexpected SMTP refusal: {refused!r}")
PYSMTPDELIVER

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
$DOCKER compose -p "$PROJECT" -f "$COMPOSE" exec -T postfix sh -lc "cat '$msg_path'" | tee /tmp/gmf-smoke-message.out | grep 'smoke-body-20260716' >/dev/null
grep '^DKIM-Signature:' /tmp/gmf-smoke-message.out >/dev/null

curl -fsS -c /tmp/gmf-roundcube.cookie http://127.0.0.1:8081/ -o /tmp/gmf-roundcube-login.html
roundcube_token=$(sed -n 's/.*name="_token" value="\([^"]*\)".*/\1/p' /tmp/gmf-roundcube-login.html | head -1)
test -n "$roundcube_token"
curl -fsS -L -b /tmp/gmf-roundcube.cookie -c /tmp/gmf-roundcube.cookie \
  -d "_token=$roundcube_token" \
  -d "_task=login" \
  -d "_action=login" \
  -d "_timezone=UTC" \
  -d "_url=" \
  -d "_user=smoke@example.test" \
  -d "_pass=smoke-secret" \
  'http://127.0.0.1:8081/?_task=login' -o /tmp/gmf-roundcube-mail.html

for _ in $(seq 1 30); do
  curl -fsS -b /tmp/gmf-roundcube.cookie 'http://127.0.0.1:8081/?_task=mail&_mbox=INBOX' -o /tmp/gmf-roundcube-inbox.html
  if grep 'GopherMailForge smoke' /tmp/gmf-roundcube-inbox.html >/dev/null; then break; fi
  curl -fsS -b /tmp/gmf-roundcube.cookie 'http://127.0.0.1:8081/?_task=mail&_action=list&_mbox=INBOX&_remote=1' -o /tmp/gmf-roundcube-list.json || true
  if grep 'GopherMailForge smoke' /tmp/gmf-roundcube-list.json >/dev/null; then break; fi
  sleep 1
done
grep -E 'GopherMailForge smoke' /tmp/gmf-roundcube-inbox.html /tmp/gmf-roundcube-list.json >/dev/null

$DOCKER compose -p "$PROJECT" -f "$COMPOSE" exec -T rspamd sh -lc 'test -s /run/rspamd/dkim/example.test.mail.key && test -s /run/rspamd/dkim/example.test.mail.txt && rspamadm configtest >/tmp/rspamd-configtest.out && grep -i "syntax OK" /tmp/rspamd-configtest.out >/dev/null'
$DOCKER compose -p "$PROJECT" -f "$COMPOSE" logs --no-color gophermailforge | grep 'postfix policy recipient=alias@example.test decision=ok' >/dev/null
$DOCKER compose -p "$PROJECT" -f "$COMPOSE" logs --no-color gophermailforge | grep 'postfix policy recipient=nobody@example.test decision=not_found' >/dev/null

cat <<'OK'
reference runtime smoke passed:
- GopherMailForge daemon contracts reachable
- doctor output exposes loud ACME/manual-certificate reference failure and plugin health
- real Postfix queried the GopherMailForge policy socket, rejected an unknown recipient, accepted SMTP, and delivered alias mail to Maildir
- real Dovecot used generated GopherMailForge-derived auth/userdb material and IMAP login/read succeeded
- Roundcube external webmail provider exposed the delivered message through its IMAP-backed mail view
- real Rspamd ran in the Postfix milter path, DKIM-signed the delivered message, and validated config
OK
