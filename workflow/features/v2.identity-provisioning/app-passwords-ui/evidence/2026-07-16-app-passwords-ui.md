# App passwords and identity UI evidence

> Superseded on 2026-09-13. This record proved only the old in-memory happy
> path. It did not prove stable label persistence, atomic SQL audit admission,
> bounded PBKDF2 work, durable runtime audit wiring, or an authentically usable
> browser identity. The feature remains `in_progress`; current evidence is
> recorded separately after the repaired gates run.

Feature: `v2.identity-provisioning.app-passwords-ui`
Timestamp: 2026-07-16 12:05 CDT

## Scope

Implemented app-password/mail-client token behavior, Dovecot verifier integration, and identity UI surfaces.

## Changes

- Added app-password create/list/revoke behavior.
- Create returns plaintext secret exactly once.
- Stored app-password records keep Authentik/Django-compatible PBKDF2-SHA256 verifier strings, not plaintext secrets.
- Revocation sets `revoked_at` and prevents future verifier acceptance.
- Existing daemon `DovecotPassdb` verification accepts SCIM-provisioned mailbox passwords and active app-password verifier records.
- Added API routes:
  - `GET /api/v1/mailboxes/{id}/app-passwords`
  - `POST /api/v1/mailboxes/{id}/app-passwords`
  - `DELETE /api/v1/mailboxes/{id}/app-passwords/{token_id}`
- Added UI sections for OIDC/Auth status, Authentik role/group mapping, SCIM status/test, app-password list/create/revoke, and permission simulator.
- App-password create/revoke, denied/failure paths, and Dovecot passdb use success/failure metadata emit audit events without logging secrets.

## Verification

- `go test ./internal/identity` passed.
- `go test ./internal/api` passed, including unauthenticated app-password rejection and daemon passdb app-password verification.
- `go test ./internal/httpui` passed, including SCIM UI test provisioning, app-password UI create/audit, and permission simulator behavior.
- `git diff --check -- .` passed.
- `go test ./...` passed.

## Coverage gaps

No accepted coverage gap for this feature surface.
