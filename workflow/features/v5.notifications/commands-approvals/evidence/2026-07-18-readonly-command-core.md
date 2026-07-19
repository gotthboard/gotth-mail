# v5 notification read-only command core evidence

Status: local command-dispatch core implemented. This is not a Telegram update receiver and not a mutation path.

## Scope

Implement the control-plane side of read-only notification commands:

- map a transport actor explicitly;
- authorize the mapped actor for the command-specific read action;
- call only a bounded summary provider;
- redact and bound returned text;
- audit every accepted/denied/failed command attempt.

## Implementation

- Added `notification.CommandService`.
- Added command names for:
  - doctor summary;
  - queue summary;
  - domain health;
  - backup status;
  - deployment status;
  - plugin health.
- Added `ActorMapper` and `CommandProvider` interfaces.
- `CommandService.Run` rejects unsupported commands, unmapped transport actors, unauthorized mapped actors, and provider failures.
- Successful responses are single bounded summaries with secret-looking values redacted and whitespace collapsed.
- The command service exposes no shell, DB handle, mutation callback, approval execution primitive, or Telegram send primitive.

## Verification

- `go test -count=1 ./internal/notification` passed.
- Tests prove unmapped Telegram actors are denied and audited.
- Tests prove mapped-but-unauthorized actors are denied.
- Tests prove authorized actors receive bounded redacted summaries.
- Tests prove provider failures are audited as failures.
- Tests prove unsupported commands are rejected; there is no generic shell command path.

## Remaining blockers

- Telegram update receiver/gRPC prompt service plumbing.
- Real read-only summary providers wired to runtime status stores.
- Live Telegram delivery proof.
- Mutation execution remains intentionally absent until end-to-end policy/audit wiring exists.
- OpenPGP/MIME signed outbound email notifications with no unsigned fallback.
