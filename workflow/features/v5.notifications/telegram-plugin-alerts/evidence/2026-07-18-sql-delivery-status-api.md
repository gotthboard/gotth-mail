# v5 SQL notification delivery status API evidence

Status: runtime/API delivery-status surface implemented for configured SQL paths.

## Scope

Expose notification delivery records to authorized operators without adding Telegram live delivery, prompt mutation authority, or approval workflow behavior.

## Implementation

- Added `notification.SQLRecorder` backed by `notification_deliveries`.
  - Records sanitized alert payload JSON.
  - Records `pending`, `delivered`, `failed_retryable`, and `failed_permanent` states.
  - Bounds failure reasons.
  - Lists the most recent 200 records.
- Added schema table `notification_deliveries` to the initial SQL schema and migration fixture.
- Added read-only API routes:
  - `GET /api/v1/notifications/deliveries`
  - `GET /api/v1/notifications/deliveries/{alert_id}`
- Routes require bearer API-token auth and `notification:read` authorization.
- `api.Server` uses `notification.SQLRecorder` automatically when `AuditDB` is configured and no explicit recorder is supplied.

## Verification

- `go test -count=1 ./internal/notification ./internal/api ./internal/store` passed.
- SQL recorder tests prove delivery state survives a fresh recorder wrapper, secret-looking alert values are redacted before storage, reasons are bounded, unknown final updates fail, and invalid statuses fail.
- API tests prove unauthenticated reads are rejected and authorized reads expose failed delivery status without leaking redacted secrets.

## Remaining blockers

- Notification-specific SendAlert/prompt protobuf service.
- Live Telegram API delivery proof with real secret/config.
- Actor mapping.
- Approval replay/mismatch/expiry protections.
- OpenPGP/MIME signed outbound email notifications with no unsigned fallback.
