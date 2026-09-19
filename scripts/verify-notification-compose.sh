#!/bin/sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
BASE="$ROOT/compose/reference/docker-compose.yml"
SIGNED="$ROOT/compose/reference/docker-compose.signed-email.yml"
DOCKER=${DOCKER:-docker}
telegram=$($DOCKER compose -f "$BASE" config)
printf '%s\n' "$telegram" | grep -q '^  notification-plugin:$'
if printf '%s\n' "$telegram" | grep -q '^  signed-email-notification-plugin:$'; then
  echo "default topology started the signed-email plugin" >&2
  exit 1
fi
printf '%s\n' "$telegram" | grep -q 'GOTTH_MAIL_NOTIFICATION_PLUGIN_NAME: telegram-notification-sink'
signed=$($DOCKER compose -f "$BASE" -f "$SIGNED" config)
printf '%s\n' "$signed" | grep -q '^  signed-email-notification-plugin:$'
if printf '%s\n' "$signed" | grep -q '^  notification-plugin:$'; then
  echo "signed-email topology started the Telegram plugin" >&2
  exit 1
fi
printf '%s\n' "$signed" | grep -q 'GOTTH_MAIL_NOTIFICATION_PLUGIN_NAME: signed-email-notification-sink'
printf '%s\n' "$signed" | grep -q 'GOTTH_MAIL_NOTIFICATION_PLUGIN_ENDPOINT: unix:///run/gotth-mail-plugins/signed-email.sock'
printf '%s\n' "$signed" | grep -q 'GOTTH_MAIL_TELEGRAM_WEBHOOK_SECRET: ""'
printf '%s\n' "$signed" | grep -A18 '^    depends_on:$' | grep -q 'signed-email-notification-plugin:'
