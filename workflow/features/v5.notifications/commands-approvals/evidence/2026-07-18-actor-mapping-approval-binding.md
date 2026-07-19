# v5 notification actor mapping and approval binding evidence

Status: local/configured SQL core implemented. This is not Telegram live delivery and does not execute mutations.

## Scope

Implement the control-plane side mechanics needed before Telegram command/approval workflows can be admitted:

- explicit transport actor mapping;
- no chat-membership-as-authorization shortcut;
- durable approval prompt binding;
- stale, replayed, mismatched, and expired approval rejection.

## Implementation

- Added `notification_actor_mappings` SQL table.
- Added `notification_approvals` SQL table.
- Added `notification.SQLActorMapper`:
  - maps `(transport, external_actor_id)` to an explicit `authz.Actor`;
  - returns unmapped actors as not found instead of granting anything;
  - stores scopes explicitly as JSON for read-only command actors.
- Added `notification.SQLApprovalStore`:
  - creates bounded approval requests with actor, transport actor, action, resource, request hash, correlation ID, and expiry;
  - confirms only when the response matches the exact original actor/action/resource/hash/transport binding;
  - rejects replay, mismatch, and expiry;
  - marks failed confirmations rejected;
  - writes audit events when an audit writer is configured.

## Verification

- `go test -count=1 ./internal/notification ./internal/store` passed.
- Tests prove unmapped Telegram actors do not map to an identity.
- Tests prove explicit mapping survives SQL reload and preserves configured scopes.
- Tests prove exact approval binding succeeds once.
- Tests prove replay is rejected.
- Tests prove changed request hash is rejected and fails closed.
- Tests prove expiry at/after deadline is rejected.
- Tests prove incomplete or already-expired approval creation fails.

## Remaining blockers

- Notification-specific SendAlert/prompt protobuf service.
- Live Telegram API delivery proof.
- Read-only command endpoint/service plumbing that uses this mapper and writes command audit events.
- Mutation execution remains intentionally absent until policy/audit paths are wired end-to-end.
- OpenPGP/MIME signed outbound email notifications with no unsigned fallback.
