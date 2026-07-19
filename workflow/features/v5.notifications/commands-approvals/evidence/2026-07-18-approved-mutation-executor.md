# v5 approved mutation executor evidence

Status: narrow local approved-mutation executor implemented and container-smoke covered. This is not a generic chat-to-shell bridge.

## Scope

Wire approved Telegram callback confirmations to a bounded mutation execution path after durable approval validation:

- explicit Telegram actor mapping;
- durable SQL approval lookup;
- exact approval confirmation through `SQLApprovalStore`;
- execute only admitted queue mutations;
- reject replay and unsupported mutations;
- write execution audit events.

## Implementation

- Added `notifyruntime.ApprovalExecutor`.
- Added `ExecuteTelegramApproval` for approval IDs and Telegram transport actors.
- Executor confirms the durable approval first, using the original action/resource/request hash from the stored approval.
- Executor supports only:
  - `queue:flush`
  - `queue:retry`
- Queue operations run through existing `ops.Queue.Flush` and `ops.Queue.Retry`, preserving their confirmation and audit behavior.
- Unsupported approved actions fail closed and are audited as execution failure.
- The executor exposes no shell, no generic action registry, and no arbitrary API mutation primitive.

## Verification

- `go test -count=1 ./internal/notifyruntime` passed.
- Tests prove queue flush executes once after approval confirmation.
- Tests prove replay is rejected.
- Tests prove unsupported mutation is not executed and is audited as failure.
- Tests prove unmapped actors are rejected before confirmation.
- `scripts/containerized-notification-plugin-smoke.sh` now runs `TestApprovalExecutor` inside the repo-owned `test-runner` container.

## Remaining blockers

- Live Telegram API delivery proof with real bot token/chat configuration.
- OpenPGP/MIME signed outbound email notifications with no unsigned fallback.
