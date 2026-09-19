#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
COMPOSE="$ROOT/compose/reference/docker-compose.yml"
OVERRIDE="$ROOT/compose/reference/webmail-runtime.override.yml"
PROJECT=${GOTTH_MAIL_WEBMAIL_RUNTIME_SMOKE_PROJECT:-gotth-mail-webmail-runtime-smoke}
DOCKER=${DOCKER:-docker}
USE_SUDO=0
GOTTH_MAIL_WEBMAIL_RUNTIME_CONFIG_SOURCE=${GOTTH_MAIL_WEBMAIL_RUNTIME_CONFIG_SOURCE:-}
GOTTH_MAIL_WEBMAIL_IMAP_PASSWORD_SOURCE=${GOTTH_MAIL_WEBMAIL_IMAP_PASSWORD_SOURCE:-}
GOTTH_MAIL_WEBMAIL_SMTP_PASSWORD_SOURCE=${GOTTH_MAIL_WEBMAIL_SMTP_PASSWORD_SOURCE:-}
GOTTH_MAIL_WEBMAIL_PRIVATE_KEY_SOURCE=${GOTTH_MAIL_WEBMAIL_PRIVATE_KEY_SOURCE:-}
GOTTH_MAIL_WEBMAIL_SMTP_USERNAME=${GOTTH_MAIL_WEBMAIL_SMTP_USERNAME:-}
GOTTH_MAIL_WEBMAIL_SMTP_PASSWORD=${GOTTH_MAIL_WEBMAIL_SMTP_PASSWORD:-}
FIXTURE=$(mktemp -d)
GNUPGHOME="$FIXTURE/gnupg"
export GNUPGHOME
mkdir -m 700 "$GNUPGHOME"
if ! $DOCKER ps >/dev/null 2>&1; then
  if command -v sudo >/dev/null 2>&1 && sudo docker ps >/dev/null 2>&1; then
    USE_SUDO=1
  else
    echo "docker daemon unavailable" >&2
    exit 1
  fi
fi
compose() {
  if [ "$USE_SUDO" = 1 ]; then
    sudo env \
      GOTTH_MAIL_WEBMAIL_RUNTIME_CONFIG_SOURCE="$GOTTH_MAIL_WEBMAIL_RUNTIME_CONFIG_SOURCE" \
      GOTTH_MAIL_WEBMAIL_IMAP_PASSWORD_SOURCE="$GOTTH_MAIL_WEBMAIL_IMAP_PASSWORD_SOURCE" \
      GOTTH_MAIL_WEBMAIL_SMTP_PASSWORD_SOURCE="$GOTTH_MAIL_WEBMAIL_SMTP_PASSWORD_SOURCE" \
      GOTTH_MAIL_WEBMAIL_PRIVATE_KEY_SOURCE="$GOTTH_MAIL_WEBMAIL_PRIVATE_KEY_SOURCE" \
      GOTTH_MAIL_WEBMAIL_SMTP_USERNAME="$GOTTH_MAIL_WEBMAIL_SMTP_USERNAME" \
      GOTTH_MAIL_WEBMAIL_SMTP_PASSWORD="$GOTTH_MAIL_WEBMAIL_SMTP_PASSWORD" \
      docker compose -p "$PROJECT" -f "$COMPOSE" -f "$OVERRIDE" "$@"
  else
    $DOCKER compose -p "$PROJECT" -f "$COMPOSE" -f "$OVERRIDE" "$@"
  fi
}
cleanup() {
  rc=$?
  if [ "$rc" -ne 0 ]; then
    compose ps >&2 || true
    compose logs --no-color --tail=200 gotth-mail postfix dovecot rspamd >&2 || true
  fi
  compose down -v --remove-orphans >/dev/null 2>&1 || true
  rm -rf "$FIXTURE"
}
trap cleanup EXIT INT TERM

gpg --batch --pinentry-mode loopback --passphrase '' --quick-generate-key \
  'GOTTH Mail Smoke <smoke@example.test>' rsa2048 sign 0 >/dev/null 2>&1
fingerprint=$(gpg --batch --with-colons --list-secret-keys smoke@example.test | awk -F: '$1=="fpr" {print $10; exit}')
test -n "$fingerprint"
gpg --batch --armor --export-secret-keys "$fingerprint" >"$FIXTURE/signing-key.asc"
printf '%s\n' 'smoke-secret' >"$FIXTURE/imap-password"
printf '%s\n' 'smoke-secret' >"$FIXTURE/smtp-password"
printf '%s\n' "{\"imap_addr\":\"dovecot:143\",\"smtp_addr\":\"postfix:25\",\"smtp_hello_name\":\"gotth-mail-webmail-smoke\",\"mailboxes\":[{\"address\":\"smoke@example.test\",\"imap_password_file\":\"/run/secrets/webmail-imap-password\",\"smtp_password_file\":\"/run/secrets/webmail-smtp-password\",\"signing_fingerprint\":\"$fingerprint\",\"private_key_file\":\"/run/secrets/webmail-signing-key.asc\"}]}" >"$FIXTURE/runtime.json"
chmod 600 "$FIXTURE/signing-key.asc" "$FIXTURE/imap-password" "$FIXTURE/smtp-password" "$FIXTURE/runtime.json"
export GOTTH_MAIL_WEBMAIL_RUNTIME_CONFIG_SOURCE="$FIXTURE/runtime.json"
export GOTTH_MAIL_WEBMAIL_IMAP_PASSWORD_SOURCE="$FIXTURE/imap-password"
export GOTTH_MAIL_WEBMAIL_SMTP_PASSWORD_SOURCE="$FIXTURE/smtp-password"
export GOTTH_MAIL_WEBMAIL_PRIVATE_KEY_SOURCE="$FIXTURE/signing-key.asc"
export GOTTH_MAIL_WEBMAIL_SMTP_USERNAME=smoke@example.test
export GOTTH_MAIL_WEBMAIL_SMTP_PASSWORD=smoke-secret

compose down -v --remove-orphans >/dev/null 2>&1 || true
compose up -d --build database gotth-mail postfix dovecot rspamd
for i in $(seq 1 90); do
  if compose exec -T postfix sh -lc 'nc -z dovecot 143 && nc -z rspamd 11332' >/dev/null 2>&1; then
    break
  fi
  [ "$i" = 90 ] && { echo "timeout waiting for reference mail services" >&2; exit 1; }
  sleep 1
done
compose build test-runner
subject="GOTTH Mail production webmail runtime $(date +%s)"
compose run --rm -T --no-deps --user 0:0 \
  -e GOTTH_MAIL_LIVE_WEBMAIL_RUNTIME_FILE=/run/secrets/webmail-runtime.json \
  -e GOTTH_MAIL_LIVE_WEBMAIL_FROM=smoke@example.test \
  -e GOTTH_MAIL_LIVE_WEBMAIL_FINGERPRINT="$fingerprint" \
  -e "GOTTH_MAIL_LIVE_WEBMAIL_SUBJECT=$subject" \
  test-runner go test -count=1 ./internal/webmail -run '^TestRuntimeRegistryLiveComposeFlow$'

echo "containerized production webmail runtime smoke passed"
