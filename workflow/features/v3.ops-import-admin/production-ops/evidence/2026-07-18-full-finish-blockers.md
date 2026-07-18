# v3 full-finish blockers

Status: in_progress/incomplete after full-finish audit and v2 interactive blocker.

Required before v3 can honestly return to done:

- Real isolated backup restore and durable backup verification records.
- Live-compatible Mailu import parser/plugin path and canonical adoption into durable state.
- SQL-backed audit query/read/redaction path and real retention.
- Canonical bulk mutations against mailbox/alias/domain storage.
- Persisted snapshots linked to verified backup state.

Current repair closed immediate audit/UI auth bypasses and removed fake UI backup success, but does not claim production operations are complete.


## 2026-07-18 SQL-backed audit query and retention progress

Closed the memory-only v3 audit read/retention seam for configured SQL deployments:

- Added `ops.SQLAuditStore` for filtered SQL audit query, detail lookup, and retention preview/apply.
- SQL audit readback preserves redacted payloads and re-redacts decoded payload fields defensively.
- SQL retention preview counts exact rows older than `older-than-Nd` cutoff.
- SQL retention apply records `audit.retention.apply` and deletes expired rows in one transaction.
- v3 audit export/detail/retention API routes now use SQL audit storage when `api.Server.AuditDB` is configured, with existing memory fallback preserved for non-SQL tests.
- Regressions cover SQL query/get/redaction/filtering, retention delete behavior, and authenticated API route wiring.

Verification:

- `go test -count=1 ./internal/ops` passed.
- `go test -count=1 ./internal/api` passed.

Remaining v3 work after this slice:

- real isolated backup restore with durable verification records
- live-compatible Mailu import/parser/plugin path
- canonical bulk mutations against durable domain/mailbox/alias storage
- persisted snapshots linked to verified backup state


## 2026-07-18 durable backup verification record progress

Closed the disposable-JSON backup verification record seam for configured SQL deployments:

- Added `ops.SQLBackupVerificationStore`.
- Successful verification records/upserts `backup_artifacts` metadata and inserts `backup_verifications` rows.
- `/api/v1/backups/verify` records SQL verification state when `api.Server.AuditDB` is configured.
- Latest verification lookup is covered for persisted rows.

Important limit:

- This does **not** claim a real isolated restore engine. `VerifyBackupFromStorage` still uses the current in-process contract restore model. The remaining v3 blocker for a true isolated restore remains open.

Verification:

- `go test -count=1 ./internal/ops` covers persisted backup artifact/verification records.
- `go test -count=1 ./internal/api` covers authenticated API backup verification writing SQL verification state.
