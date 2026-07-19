# v5 runtime read-only command provider evidence

Status: local runtime summary provider implemented and added to container smoke. This is not a Telegram receiver and not a mutation path.

## Scope

Replace fake read-only command responses with bounded summaries derived from existing runtime state objects:

- doctor report;
- Postfix queue summary;
- domain/mailbox/alias state;
- latest backup verification state;
- deployment snapshot state;
- plugin registration state.

## Implementation

- Added `internal/notifyruntime.RuntimeCommandProvider` outside the core `notification` package to avoid import-cycle garbage and keep notification primitives independent.
- Provider implements `notification.CommandProvider`.
- Provider returns unavailable summaries when runtime state is not wired instead of inventing status.
- Provider uses existing `ops`, `daemon`, and `plugin` state structs. It does not execute shell commands, read logs, call Docker, or expose mutation authority.
- The notification plugin container smoke now also runs `TestRuntimeCommandProvider` inside `test-runner`.

## Verification

- `go test -count=1 ./internal/notification ./internal/notifyruntime` passed.
- Tests cover doctor, queue, domain, backup, deployment, plugin summaries, unavailable state, and unsupported command rejection.
- `scripts/containerized-notification-plugin-smoke.sh` now includes `./internal/notifyruntime` provider tests in the repo-owned container path.

## Remaining blockers

- Real Telegram update receiver connected to `CommandService` and `SQLApprovalStore`.
- Live Telegram API delivery proof with real bot token/chat configuration.
- Mutation execution remains intentionally absent until end-to-end policy/audit wiring exists.
- OpenPGP/MIME signed outbound email notifications with no unsigned fallback.
