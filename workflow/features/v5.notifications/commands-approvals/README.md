# Read-only commands, actor mapping, approval bindings

ID: `v5.notifications.commands-approvals`

State: `done`

The configured webhook requires Telegram's secret-token header, maps the exact
chat/user pair to a core actor, authorizes and audits bounded read-only
commands, and returns Telegram-compatible webhook replies. Approval prompts
carry a store-generated 128-bit one-time token while SQL stores only its
SHA-256 binding. Core re-authorizes, rejects replay/expiry/state drift, and can
execute only queue flush or retry. No generic chat-to-shell path exists.

Canonical state lives in `workflow.toml`. This folder holds scoped evidence, review notes, and postmortems only.
