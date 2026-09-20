#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
PREFIX=${GOTTH_MAIL_PRODUCTION_SMOKE_PREFIX:-gotth-mail-production-smoke}
POSTGRES_IMAGE=${GOTTH_MAIL_POSTGRES_IMAGE:-postgres@sha256:a426e44bac0b759c95894d68e1a0ac03ecc20b619f498a91aae373bf06d8508d}
WORK=$(mktemp -d -t gotth-mail-production-smoke.XXXXXX)
NETWORK="$PREFIX-private"

DOCKER=(docker)
if ! "${DOCKER[@]}" info >/dev/null 2>&1; then
  DOCKER=(sudo -n docker)
fi

containers=(db control-plane front postfix dovecot rspamd)
cleanup() {
  local rc=$?
  if [ "$rc" -ne 0 ]; then
    for role in "${containers[@]}"; do
      "${DOCKER[@]}" logs --tail 160 "$PREFIX-$role" >&2 || true
    done
  fi
  for role in "${containers[@]}"; do
    "${DOCKER[@]}" rm -f "$PREFIX-$role" >/dev/null 2>&1 || true
  done
  "${DOCKER[@]}" network rm "$NETWORK" >/dev/null 2>&1 || true
  if command -v sudo >/dev/null 2>&1; then
    sudo -n chown -R "$(id -u):$(id -g)" "$WORK" >/dev/null 2>&1 || true
  fi
  rm -rf "$WORK"
}
trap cleanup EXIT
cleanup

mkdir -p "$WORK"/{database,control,queue,mail,rspamd,dkim,secrets,tls}
mkdir -p "$WORK/control/extensions"/{artifacts,runtime}
chmod 0700 "$WORK/control/extensions/runtime"
umask 077
printf '%s' 'production-smoke-database-password' >"$WORK/secrets/postgres-password"
printf '%s' 'postgres://gotth_mail:production-smoke-database-password@postgres/gotth_mail?sslmode=disable' >"$WORK/secrets/database-url"
printf '%s' 'front_auth_token_0123456789_ABCDEFGHIJ' >"$WORK/secrets/front-auth-token"
printf '%s' 'postfix_helper_token_0123456789_ABCDEF' >"$WORK/secrets/postfix-helper-token"
printf '%s' 'postfix_release_token_0123456789_ABCDE' >"$WORK/secrets/postfix-release-token"
printf '%s' 'rspamd_controller_token_0123456789_AB' >"$WORK/secrets/rspamd-controller-token"
printf '%s' 'oidc_smoke_secret_not_configured' >"$WORK/secrets/oidc-client-secret"
printf '%s' '0123456789abcdef0123456789abcdef' >"$WORK/secrets/master-key"
chmod 0400 "$WORK"/secrets/*

openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj '/CN=mail.example.test' \
  -addext 'subjectAltName=DNS:mail.example.test' -keyout "$WORK/tls/private-key.pem" \
  -out "$WORK/tls/certificate.pem" >/dev/null 2>&1
chmod 0400 "$WORK/tls/private-key.pem" "$WORK/tls/certificate.pem"
chmod 0444 "$WORK/secrets/postgres-password"

if command -v sudo >/dev/null 2>&1; then
  sudo -n chown -R 1000:1000 "$WORK/control" "$WORK/mail" "$WORK/rspamd" "$WORK/dkim" "$WORK/tls" "$WORK/secrets"
  sudo -n chown -R 999:999 "$WORK/database" "$WORK/secrets/postgres-password"
fi

source_commit=${GOTTH_MAIL_SOURCE_COMMIT:-$(git -C "$ROOT" rev-parse HEAD)}
for role in control-plane front postfix dovecot rspamd; do
  image="gotth-mail-production:$role"
  if [ "${GOTTH_MAIL_SMOKE_BUILD:-0}" = 1 ] || ! "${DOCKER[@]}" image inspect "$image" >/dev/null 2>&1; then
    "${DOCKER[@]}" build --platform linux/amd64 --target "$role" \
      --build-arg VERSION=1.0.0-alpha.1 --build-arg SOURCE_COMMIT="$source_commit" \
      -t "$image" -f "$ROOT/build/production/Dockerfile" "$ROOT"
  fi
done

"${DOCKER[@]}" network create "$NETWORK" >/dev/null

"${DOCKER[@]}" run -d --name "$PREFIX-db" --network "$NETWORK" --network-alias postgres \
  --read-only --cap-drop ALL --security-opt no-new-privileges --user 999:999 \
  --tmpfs /tmp:rw,noexec,nosuid,nodev,size=67108864 \
  --tmpfs /run/postgresql:rw,noexec,nosuid,nodev,size=16777216 \
  -e POSTGRES_USER=gotth_mail -e POSTGRES_DB=gotth_mail \
  -e POSTGRES_PASSWORD_FILE=/run/secrets/postgres-password \
  -v "$WORK/database:/var/lib/postgresql/data" \
  -v "$WORK/secrets/postgres-password:/run/secrets/postgres-password:ro" \
  "$POSTGRES_IMAGE" >/dev/null

for _ in $(seq 1 90); do
  if "${DOCKER[@]}" exec "$PREFIX-db" pg_isready -U gotth_mail -d gotth_mail >/dev/null 2>&1; then break; fi
  if [ "$("${DOCKER[@]}" inspect -f '{{.State.Running}}' "$PREFIX-db" 2>/dev/null || true)" != true ]; then
    echo 'PostgreSQL stopped before becoming ready' >&2
    "${DOCKER[@]}" logs "$PREFIX-db" >&2 || true
    exit 1
  fi
  sleep 1
done
"${DOCKER[@]}" exec "$PREFIX-db" pg_isready -U gotth_mail -d gotth_mail >/dev/null

run_control() {
  "${DOCKER[@]}" run -d --name "$PREFIX-control-plane" --network "$NETWORK" --network-alias control-plane \
    --read-only --cap-drop ALL --security-opt no-new-privileges --user 1000:1000 \
    -p 127.0.0.1:18080:8080 \
    --tmpfs /tmp:rw,noexec,nosuid,nodev,size=67108864 --tmpfs /run:rw,noexec,nosuid,nodev,size=16777216,uid=1000,gid=1000,mode=0700 \
    -v "$ROOT/configs/production:/etc/gotth-mail:ro" -v "$WORK/control:/var/lib/gotth-mail" \
    -v "$WORK/secrets/database-url:/run/secrets/database-url:ro" \
    -v "$WORK/secrets/master-key:/run/secrets/master-key:ro" \
    -v "$WORK/secrets/front-auth-token:/run/secrets/front-auth-token:ro" \
    -v "$WORK/secrets/oidc-client-secret:/run/secrets/oidc-client-secret:ro" \
    -v "$WORK/secrets/postfix-helper-token:/run/secrets/postfix-helper-token:ro" \
    -v "$WORK/secrets/postfix-release-token:/run/secrets/postfix-release-token:ro" \
    gotth-mail-production:control-plane >/dev/null
}

wait_health() {
  local role=$1 attempts=${2:-90}
  for _ in $(seq 1 "$attempts"); do
    if "${DOCKER[@]}" exec "$PREFIX-$role" /usr/local/bin/gotth-mail-health "$role" >/dev/null 2>&1; then return 0; fi
    if [ "$("${DOCKER[@]}" inspect -f '{{.State.Running}}' "$PREFIX-$role" 2>/dev/null || true)" != true ]; then
      echo "$role stopped before becoming healthy" >&2
      "${DOCKER[@]}" logs "$PREFIX-$role" >&2 || true
      return 1
    fi
    sleep 1
  done
  echo "$role did not become healthy" >&2
  return 1
}

run_control
wait_health control-plane
"${DOCKER[@]}" rm -f "$PREFIX-control-plane" >/dev/null

verifier=$(python3 - <<'PY'
import base64, hashlib
secret = b'production-smoke-mail-secret'
salt = b'production-smoke-salt'
digest = hashlib.pbkdf2_hmac('sha256', secret, salt, 1200, dklen=32)
print('pbkdf2_sha256$1200$production-smoke-salt$' + base64.b64encode(digest).decode())
PY
)
"${DOCKER[@]}" exec -i "$PREFIX-db" psql -v ON_ERROR_STOP=1 -U gotth_mail -d gotth_mail >/dev/null <<SQL
INSERT INTO domains(id,name,enabled,outbound_scope,outbound_policy_revision,created_at,updated_at)
VALUES ('10000000-0000-4000-8000-000000000001','example.test',true,'same_domain_only',1,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP);
INSERT INTO mailboxes(id,domain_id,local_part,enabled,verifier,created_at,updated_at)
VALUES ('10000000-0000-4000-8000-000000000002','10000000-0000-4000-8000-000000000001','user',true,'$verifier',CURRENT_TIMESTAMP,CURRENT_TIMESTAMP);
SQL

run_control
wait_health control-plane

"${DOCKER[@]}" run -d --name "$PREFIX-rspamd" --network "$NETWORK" --network-alias rspamd \
  --read-only --cap-drop ALL --security-opt no-new-privileges --user 1000:1000 \
  --tmpfs /tmp:rw,noexec,nosuid,nodev,size=67108864 --tmpfs /run:rw,noexec,nosuid,nodev,size=16777216,uid=1000,gid=1000,mode=0700 \
  -v "$ROOT/configs/production:/etc/gotth-mail:ro" -v "$WORK/rspamd:/var/lib/rspamd" \
  -v "$WORK/dkim:/var/lib/gotth-mail/dkim:ro" \
  -v "$WORK/secrets/rspamd-controller-token:/run/secrets/controller-token:ro" \
  gotth-mail-production:rspamd >/dev/null
wait_health rspamd 120

"${DOCKER[@]}" run -d --name "$PREFIX-dovecot" --network "$NETWORK" --network-alias dovecot \
  --read-only --cap-drop ALL --cap-add CHOWN --cap-add DAC_OVERRIDE --cap-add DAC_READ_SEARCH \
  --cap-add FOWNER --cap-add NET_BIND_SERVICE --cap-add SETGID --cap-add SETUID --cap-add SYS_CHROOT \
  --security-opt no-new-privileges --user 0:0 \
  --tmpfs /tmp:rw,noexec,nosuid,nodev,size=67108864 --tmpfs /run:rw,noexec,nosuid,nodev,size=16777216,uid=1000,gid=1000,mode=0700 \
  -v "$ROOT/configs/production:/etc/gotth-mail:ro" -v "$WORK/mail:/var/lib/gotth-mail/mail" \
  -v "$WORK/secrets/front-auth-token:/run/secrets/control-token:ro" \
  gotth-mail-production:dovecot >/dev/null
wait_health dovecot

"${DOCKER[@]}" run -d --name "$PREFIX-postfix" --network "$NETWORK" --network-alias postfix \
  --read-only --cap-drop ALL --cap-add CHOWN --cap-add DAC_OVERRIDE --cap-add DAC_READ_SEARCH \
  --cap-add FOWNER --cap-add NET_BIND_SERVICE --cap-add SETGID --cap-add SETUID \
  --security-opt no-new-privileges --user 0:0 \
  --tmpfs /tmp:rw,noexec,nosuid,nodev,size=67108864 --tmpfs /run:rw,noexec,nosuid,nodev,size=16777216,uid=1000,gid=1000,mode=0700 \
  -v "$ROOT/configs/production:/etc/gotth-mail:ro" -v "$WORK/queue:/var/spool/postfix" \
  -v "$WORK/secrets/postfix-helper-token:/run/secrets/postfix-helper-token:ro" \
  -v "$WORK/secrets/postfix-release-token:/run/secrets/postfix-release-token:ro" \
  gotth-mail-production:postfix >/dev/null
wait_health postfix

front_auth_status=$(curl -fsS -D - -o /dev/null \
  -H 'X-GOTTH-Mail-Front-Token: front_auth_token_0123456789_ABCDEFGHIJ' \
  -H 'Auth-Protocol: smtp' -H 'Auth-Method: none' -H 'Auth-SMTP-To: user@example.test' \
  http://127.0.0.1:18080/internal/v1/front/auth | tr -d '\r' | sed -n 's/^Auth-Status: //p')
test "$front_auth_status" = OK

"${DOCKER[@]}" run -d --name "$PREFIX-front" --network "$NETWORK" --network-alias front \
  --read-only --cap-drop ALL --security-opt no-new-privileges --user 1000:1000 \
  --tmpfs /tmp:rw,noexec,nosuid,nodev,size=67108864 --tmpfs /run:rw,noexec,nosuid,nodev,size=16777216,uid=1000,gid=1000,mode=0700 \
  -p 127.0.0.1:2525:1025 -p 127.0.0.1:2465:1465 -p 127.0.0.1:2587:1587 \
  -p 127.0.0.1:2143:1143 -p 127.0.0.1:2993:1993 \
  -v "$ROOT/configs/production:/etc/gotth-mail:ro" \
  -v "$WORK/tls/certificate.pem:/run/gotth-mail/tls/certificate.pem:ro" \
  -v "$WORK/tls/private-key.pem:/run/gotth-mail/tls/private-key.pem:ro" \
  -v "$WORK/secrets/front-auth-token:/run/secrets/front-auth-token:ro" \
  gotth-mail-production:front >/dev/null
wait_health front

python3 - <<'PY'
import smtplib, ssl
from email.message import EmailMessage

context = ssl._create_unverified_context()
message = EmailMessage()
message['Subject'] = 'production boundary smoke'
message['From'] = 'outside@example.net'
message['To'] = 'user@example.test'
message.set_content('production-boundary-smoke-body')
with smtplib.SMTP('127.0.0.1', 2525, timeout=30) as smtp:
    smtp.ehlo('smoke.example.net')
    smtp.starttls(context=context)
    smtp.ehlo('smoke.example.net')
    refused = smtp.send_message(message)
    if refused:
        raise SystemExit(f'unexpected SMTP refusal: {refused!r}')
PY

delivered=
for _ in $(seq 1 30); do
  delivered=$("${DOCKER[@]}" exec "$PREFIX-dovecot" find /var/lib/gotth-mail/mail -type f -path '*/Maildir/new/*' -print -quit)
  if [ -n "$delivered" ]; then break; fi
  sleep 1
done
test -n "$delivered"

python3 - <<'PY'
import imaplib, ssl, time

context = ssl._create_unverified_context()
last_error = None
for _ in range(10):
    try:
        with imaplib.IMAP4_SSL('127.0.0.1', 2993, ssl_context=context, timeout=3) as imap:
            imap.login('user@example.test', 'production-smoke-mail-secret')
            status, _ = imap.select('INBOX')
            if status != 'OK':
                raise RuntimeError('INBOX selection failed')
            status, data = imap.search(None, 'SUBJECT', '"production boundary smoke"')
            if status == 'OK' and data and data[0]:
                break
    except (imaplib.IMAP4.error, OSError) as error:
        last_error = error
    time.sleep(1)
else:
    raise SystemExit(f'delivered message was not readable through authenticated IMAPS: {last_error}')
PY

printf '%s\n' 'production runtime smoke passed: control plane, NGINX TLS/auth, Postfix, Rspamd, Dovecot LMTP, Maildir, and authenticated IMAPS'
