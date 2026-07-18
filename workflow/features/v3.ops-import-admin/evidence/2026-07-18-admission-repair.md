# v3 admission repair evidence

Root feature: `v3.ops-import-admin`
Timestamp: 2026-07-18 CDT

## Repair slice

Layered vertical slice: operator API authority, server-bound preview/apply state, audit durability, and validation cleanup.

## What changed

- v3 operator API routes now require bearer-token authentication and `ops:admin` authorization instead of using a fabricated local-admin actor.
- Snapshot read/diff paths no longer manufacture rollback status from query-string values; unknown snapshot IDs return not found.
- Audit event detail reads redact through `audit.Redact` at the API boundary.
- Bulk preview rejects empty/blank scope.
- Bulk apply writes required per-item audit records before mutating modeled state and fails closed on audit write errors.
- Mailu import preview now rejects invalid domain/address candidates and malformed Django PBKDF2 verifier strings instead of accepting loose placeholders.

## Verification

- `go test ./internal/api` passed after the v3 route/auth/snapshot changes.
- `go test ./internal/ops` passed after import/bulk validation and audit durability changes.
- `git diff --check -- .` passed.
- `go test ./...` passed.

## Remaining gaps

- Backup verification remains a modeled restore/contract seam, not a live isolated container/database restore.
- Mailu import compatibility is still fixture-level validation, not a live Mailu export/import integration.
