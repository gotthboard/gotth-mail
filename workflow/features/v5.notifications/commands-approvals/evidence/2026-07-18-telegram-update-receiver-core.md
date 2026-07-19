# v5 Telegram update receiver core evidence

Status: local Telegram update receiver core implemented and container-smoke covered. This does not call the live Telegram API and does not execute mutations.

## Scope

Connect Telegram-shaped inbound updates to existing bounded core services:

- read-only slash commands route through `CommandService`;
- command actors must resolve through explicit `(transport, external_actor_id)` mapping;
- command authorization remains command-specific;
- approval callbacks route through `SQLApprovalStore` binding checks;
- approval callback actors must match the original mapped transport actor;
- replay/mismatch/expiry protections remain in the SQL approval store.

## Implementation

- Added `notification.TelegramReceiver`.
- Added bounded HTTP handler for Telegram-style JSON update payloads.
- Added supported read-only commands:
  - `/doctor`
  - `/queue`
  - `/domains`
  - `/backup`
  - `/deploy` or `/deployment`
  - `/plugins`
- Added callback parser for `gmf:approve:<approval_id>`.
- Approval callbacks look up the durable approval request, map the Telegram actor, and call `Confirm` with the original action/resource/request hash. The receiver itself does not execute the approved mutation.
- Unsupported commands/callbacks produce bounded local replies instead of shell execution.

## Verification

- `go test -count=1 ./internal/notification` passed.
- Tests prove read-only command routing through `CommandService`.
- Tests prove unmapped command actors are denied.
- Tests prove approval callbacks confirm through SQL once and replay is rejected.
- Tests prove a different Telegram actor cannot confirm another actor's approval.
- Tests prove the HTTP handler rejects wrong method and bad JSON.
- `scripts/containerized-notification-plugin-smoke.sh` now runs `TestTelegramReceiver` inside the repo-owned `test-runner` container.

## Remaining blockers

- Live Telegram API delivery proof with real bot token/chat configuration.
- Mutation execution remains intentionally absent until end-to-end policy/audit execution wiring exists.
- OpenPGP/MIME signed outbound email notifications with no unsigned fallback.
