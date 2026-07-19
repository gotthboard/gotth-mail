# v5 notification backend gRPC smoke evidence

Status: notification-specific protobuf/gRPC alert and prompt service implemented and covered in the repo-owned plugin container. This is not live Telegram API delivery.

## Scope

Add the notification backend RPC seam required after the generic plugin-control seam:

- `NotificationBackend.SendAlert`;
- `NotificationBackend.SendPrompt`;
- service-identity authentication through existing gRPC metadata;
- prompt delivery only, not approval confirmation or mutation execution.

## Implementation

- Extended `proto/gophermailforge/plugin/v1/plugin.proto` with `NotificationBackend`.
- Regenerated checked-in Go protobuf/gRPC bindings using pinned generators.
- Added `plugin.NotificationServer` and `LocalNotificationSink`.
- The notification plugin container registers `NotificationBackend` only for notification seam plugins.
- Alert payloads are validated through the core notification sanitizer before delivery acceptance.
- Prompt payloads must include complete binding fields and reject secret-looking prompt text.
- First notification plugin capabilities now include `notification.alert.send` and `notification.prompt.send`.
- Existing container smoke now exercises both generic plugin-control RPCs and notification-specific alert/prompt RPCs.

## Verification

- `go test -count=1 ./internal/plugin ./cmd/gmf-plugin ./proto/gophermailforge/plugin/v1` passed.
- Local gRPC tests prove authenticated alert/prompt delivery, wrong-token rejection, invalid alert rejection, and unsafe prompt rejection.
- Container smoke command is `scripts/containerized-notification-plugin-smoke.sh`; it now runs `TestLivePluginControlOverGRPC|TestLiveNotificationBackendOverGRPC` against the Compose `notification-plugin` service.

## Remaining blockers

- Live Telegram API delivery proof with real bot token/chat configuration.
- Real Telegram update receiver connected to `CommandService` and `SQLApprovalStore`.
- Real runtime summary providers for read-only commands.
- Mutation execution remains intentionally absent until end-to-end policy/audit wiring exists.
- OpenPGP/MIME signed outbound email notifications with no unsigned fallback.
