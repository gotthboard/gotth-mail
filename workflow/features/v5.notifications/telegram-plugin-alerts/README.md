# Telegram notification plugin and operational alerts

ID: `v5.notifications.telegram-plugin-alerts`

State: `done`

The production plugin now delivers bounded redacted alerts and one-time
approval prompts through the Telegram Bot API. Only the explicit reference
fixture retains the local acceptance sink. Core selects the plugin over
authenticated bounded-deadline gRPC and records final delivery status in SQL.

Live use still requires an operator-owned bot token, allowlisted chat IDs,
webhook secret, and Telegram-side webhook registration. Those deployment
inputs were not fabricated during repository admission.

Canonical state lives in `workflow.toml`. This folder holds scoped evidence, review notes, and postmortems only.
