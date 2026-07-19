# v5 containerized notification plugin gRPC smoke evidence

Status: notification plugin container/control-plane gRPC seam added and verified.

## Scope

Add a repo-owned notification plugin container to the reference Compose topology and prove authenticated gRPC plugin control works from a containerized test runner.

This is a transport/control seam smoke, not live Telegram delivery. No Telegram bot token is used, no Telegram API call is made, and no approval workflow is enabled.

## Implementation

- Added `telegram-notification-sink` as a first mechanism plugin registration:
  - seam: `notification`
  - endpoint: `notification-plugin:9443`
  - capabilities: `notification.alert.sink`, `notification.delivery.status`
- Added `notification-plugin` service to `compose/reference/docker-compose.yml` using the existing `gmf-plugin` runner.
- Added env-gated `TestLivePluginControlOverGRPC` in `internal/plugin/grpc_test.go`.
  - Connects to a live plugin endpoint.
  - Requires deadline, correlation metadata, and plugin service token.
  - Verifies health, version/name, notification capabilities, and wrong-token rejection.
- Added `scripts/containerized-notification-plugin-smoke.sh`.
  - Starts the Compose notification plugin container.
  - Runs the live gRPC control test inside the Compose `test-runner` container.
- Added contract coverage so the notification plugin service and smoke script cannot silently disappear.

## Verification

- `go test -count=1 ./internal/plugin ./test/contract` passed.
- `git diff --check -- .` passed.
- `scripts/containerized-notification-plugin-smoke.sh` passed.
  - The Docker build stage ran `go test ./...` inside the container.
  - The live gRPC control test reached `notification-plugin:9443` from the test-runner container.
  - The test verified authenticated health/version/capability calls and unauthenticated wrong-token rejection.

## Remaining blockers

- Notification-specific `SendAlert`/prompt protobuf service is still not implemented.
- Live Telegram delivery proof still requires Telegram bot/runtime secrets and an allowed chat mapping.
- Runtime/API delivery status surface remains incomplete.
- Actor mapping remains incomplete.
- Approval replay/mismatch/expiry protections remain incomplete.
- OpenPGP/MIME signed outbound email notifications with no unsigned fallback remain incomplete.
