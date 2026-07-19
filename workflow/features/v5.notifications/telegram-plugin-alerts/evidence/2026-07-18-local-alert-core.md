# v5 local notification alert core evidence

Status: local alert-core slice implemented; notification plugin container/control gRPC smoke added separately; v5 remains incomplete and must not be called Telegram/OpenPGP notification complete.

## Scope

Implement the notification core alert contract, sanitizer, and delivery-status recorder with fake backend tests. No Telegram sends, no live service, no approval workflow, no OpenPGP private keys, and no workflow done claim.

## Implementation

- Added `internal/notification` package.
- Defined `Alert`, `Severity`, `ResourceRef`, `DeliveryStatus`, `DeliveryResult`, `Backend`, `Recorder`, and `DeliveryRecord`.
- Added `Service.SendAlert`, which sanitizes and bounds alert payloads, records `pending`, calls only the injected backend interface, records final delivery status, and returns queryable delivery state.
- Follow-up repair added `notification.SQLRecorder` and read-only API routes for configured SQL delivery status visibility.
- Added `MemoryRecorder` for tests/local use.
- Redacts secret-looking values before backend delivery.
- Rejects broad multiline/raw-log-like details and oversized detail maps.
- Bounds title, summary, detail values, correlation IDs, class, and resource fields deterministically.
- Backend receives only `SendAlert(ctx, Alert)`; no DB handle, control-plane store, approval callback, or mutation path is exposed.

## Tests

- Delivered status is recorded after fake backend success.
- Retryable backend failure is visible in stored delivery status/reason.
- Secret-looking payloads are redacted before backend delivery.
- Oversized alert text is bounded and broad multiline log blobs are rejected.
- Backend receives only the sanitized alert contract.

## Verification

- `go test -count=1 ./internal/notification ./internal/webmail ./internal/api ./internal/store` passed.

## Remaining v5 blockers

- Notification plugin container/control-plane gRPC smoke is covered in `2026-07-18-containerized-notification-plugin-grpc-smoke.md`; notification-specific SendAlert/prompt protobuf service remains incomplete.
- Live Telegram API delivery proof.
- Delivery failure reporting through the real runtime/API surface. **Repaired for configured SQL paths on 2026-07-18; see `2026-07-18-sql-delivery-status-api.md`.**
- Actor mapping and approval binding/replay/mismatch/expiry protections. **Repaired for configured SQL core paths on 2026-07-18; see `../../commands-approvals/evidence/2026-07-18-actor-mapping-approval-binding.md`.**
- OpenPGP/MIME signed outbound email notifications with exact-sender key-state matrix.
- No unsigned email fallback is allowed.
