# Production notification runtime admission — 2026-09-19

Candidate line: `de21330` plus the cold-review repair commit under review

## Admitted behavior

- The Telegram plugin uses the real Bot API in production configuration. The
  in-memory success sink is reachable only through the explicit reference
  fixture switch.
- Core selects Telegram or mandatory-OpenPGP signed email over authenticated
  gRPC with a five-second upper deadline and stores pending/final delivery
  state and typed evidence in PostgreSQL. Production gRPC is restricted to
  loopback or a shared Unix socket; the reference Compose stack uses the
  socket instead of sending bearer credentials over container TCP.
- Telegram alerts are bounded and redacted. Prompt delivery is restricted to
  configured chat IDs and carries a 64-byte-safe one-time approval callback.
- Webhooks require the Telegram secret-token header, exact mapped chat/user
  identity, command-specific authorization, bounded authoritative summaries,
  audit, HTTP-200 application denials, and durable update-ID deduplication.
- Approval tokens are generated from `crypto/rand`; only SHA-256 bindings are
  durable. Replay, expiry, binding mismatch, unauthorized actors, unsupported
  actions, and changed live Postfix snapshots fail closed. The privileged
  helper admits only documented `postqueue -f` and exact-ID `postqueue -i`
  scheduling operations. Leased SQL execution recovers crash/failure paths;
  success consumption and audit commit transactionally.
- The owner-only Telegram actor mapping file transactionally replaces the
  configured mapping set. Operational doctor, certificate, backup, queue,
  abuse/rate-limit, deployment, and plugin-health events have production
  dispatch points through the configured delivery service.
- Plugin status responses no longer serialize service credentials.
- Migration `0013_notification_approval_binding` rejects legacy unbound
  prompts; `0014_notification_approval_execution` adds recoverable execution
  state and `0015_notification_telegram_updates` adds webhook deduplication.

## Verification

- `go test -p=2 ./...`
- `go test -race -p=2 ./internal/notification ./internal/notifyruntime ./internal/outboundpolicy ./internal/postfixgate ./internal/api ./cmd/gotth-mail ./cmd/gotth-mail-plugin ./cmd/gotth-mail-postfix-gate`
- `go vet ./...`
- `scripts/containerized-notification-plugin-smoke.sh`
- normal and signed-email-profile `docker compose config`
- focused SQL migration, gRPC, Telegram API, webhook, command, approval,
  exact-sender email, and secret-redaction tests
- `git diff --check`

## Deployment boundary

No live Telegram request, webhook registration, production credential,
mailbox, queue, deployment, DNS record, signing key, tag, release, or remote
repository changed. A live operator must provide the bot token, chat allowlist,
webhook secret/registration, actor mappings, and production signing-key custody.
