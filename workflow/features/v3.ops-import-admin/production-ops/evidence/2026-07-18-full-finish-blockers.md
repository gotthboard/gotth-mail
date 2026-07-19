# v3 full-finish blockers

Status: implementation repaired for configured SQL/local-test paths; root admission remains constrained by the v2 live Authentik blocker and manifest dependencies.

Repaired v3 production-ops surfaces:

- Real isolated SQL backup restore and durable backup verification records for configured SQL paths.
- Live-compatible Mailu import parsing from `config-export --json`, password preservation from `config-export --secrets --json`, canonical SQL adoption for domains/mailboxes/aliases/relays, and repo-owned containerized Mailu import smoke coverage.
- SQL-backed audit query/read/redaction path and real retention.
- Canonical SQL bulk mutations against mailbox/alias storage.
- Persisted snapshots linked to verified backup state.

Remaining admission constraint:

- Do not mark downstream roots done while v2's live Authentik browser/passkey callback and group-claim proof remain blocked. v3 implementation evidence can be complete without pretending the dependency chain is complete.


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

Remaining v3 work after this slice was later addressed by the SQL restore and Mailu import sections below.


## 2026-07-18 durable backup verification record progress

Closed the disposable-JSON backup verification record seam for configured SQL deployments:

- Added `ops.SQLBackupVerificationStore`.
- Successful verification records/upserts `backup_artifacts` metadata and inserts `backup_verifications` rows.
- `/api/v1/backups/verify` records SQL verification state when `api.Server.AuditDB` is configured.
- Latest verification lookup is covered for persisted rows.

Historical limit at this slice: this did not yet claim a real isolated restore engine. The later isolated SQL restore section below repaired that for configured SQL paths.

Verification:

- `go test -count=1 ./internal/ops` covers persisted backup artifact/verification records.
- `go test -count=1 ./internal/api` covers authenticated API backup verification writing SQL verification state.


## 2026-07-18 isolated SQL restore engine progress

Closed the in-process-only restore verification seam for configured SQL restore paths:

- Added an `IsolatedRestoreEngine` contract and `SQLIsolatedRestoreEngine` implementation.
- The SQL restore engine migrates an isolated empty SQL database, restores domain/mailbox/alias artifact state into canonical tables, reloads daemon contract state from SQL, and only then runs daemon recipient contract verification.
- Backup verification records now preserve the restore-engine reference through `backup_verifications.isolated_restore_ref` when no explicit override is supplied.
- The v3 backup verification API uses the configured runtime restore engine when SQL verification recording is enabled.
- The legacy local contract restore remains only as compatibility fallback for unconfigured/non-SQL callers; it is no longer the only mechanism available.

Historical limit at this slice: live Mailu import compatibility, canonical durable bulk mutations, and persisted snapshot linkage were still open here. Later sections below repaired those configured-path gaps.

Verification:

- `go test -count=1 ./internal/ops` passed with SQL isolated restore, dirty restore DB rejection, and persisted restore-ref coverage.
- `go test -count=1 ./internal/api` passed with API backup verification using a configured SQL isolated restore engine and persisting its restore reference.


## 2026-07-18 persisted SQL snapshot linkage progress

Closed the in-memory-only snapshot listing/diff seam for configured SQL deployments:

- Added `ops.SQLSnapshotStore` for persisted snapshot capture, list, and lookup.
- Persisted snapshots now link to `backup_verifications.linked_backup_verification_id` and derive `VerifiedRestoreStatus` from the referenced verification row.
- The v3 snapshot API reads SQL snapshots when `api.Server.AuditDB` is configured, including list, detail/rollback guidance, and diff routes.
- Rollback guidance now operates on persisted verified-restore status for configured SQL deployments instead of only runtime map state.

Historical limit at this slice: live Mailu import compatibility and canonical durable bulk mutations were still open here. Later sections below repaired those configured-path gaps.

Verification:

- `go test -count=1 ./internal/ops` passed with persisted snapshot/verified-backup linkage coverage.
- `go test -count=1 ./internal/api` passed with snapshot list/detail/diff API routes reading SQL-backed snapshots.


## 2026-07-18 Mailu live export/password preservation progress

Closed the fake-parser/password-preservation and configured-SQL apply seam for Mailu import preview/apply:

- Added live Mailu `config-export --json` object parsing for `domain`, `user`, `alias`, and `relay` arrays while preserving the legacy synthetic candidate-array test path.
- Added local Mailu fixture exports under `test/fixtures/mailu/` for redacted and secret export shapes.
- Added repo-owned Compose `mailu-import` fixture and containerized smoke script so live Mailu export compatibility no longer depends on an ad hoc host setup.
- Preserved Mailu Passlib `bcrypt-sha256` user password hashes as `mailu_bcrypt_sha256$<original-mailu-passlib-hash>` using Bryce's proven Authentik custom-hasher migration rule.
- Rejected redacted non-secret password exports for user password preservation.
- Preserved multi-destination aliases from the live Mailu export shape.
- Added `ops.SQLImportStore` to apply admissible Mailu import previews into canonical SQL `domains`, `mailboxes`, `aliases`, and `relays` tables when a DB is configured.
- Reloaded daemon state from SQL after import commit and verified imported recipients against persisted state.
- Routed `/api/v1/imports/mailu/apply` through SQL import plus durable SQL audit when `api.Server.AuditDB` is configured.
- Documented that this is an Authentik migration-preservation exception, not Django `bcrypt_sha256` conversion and not native local Dovecot verifier support.

Important limit:

- This does **not** remove the v2 live Authentik browser/passkey blocker or automatically admit downstream roots that depend on v2.

Verification:

- `go test -count=1 ./internal/ops` passed with live Mailu export fixture coverage.
- `go test -count=1 ./internal/ops ./internal/api` passed with canonical SQL import apply and API route coverage.
- `scripts/containerized-mailu-import-smoke.sh` passed with Mailu admin/Redis fixture containers and containerized focused import/API tests.


## 2026-07-18 durable SQL bulk mutation progress

Closed the memory-only bulk mutation seam for configured SQL deployments:

- Added `ops.SQLBulkStore` for canonical SQL bulk apply against `mailboxes` and `aliases`.
- `disable-users` and `enable-users` now update canonical mailbox rows when SQL is configured.
- `delete-aliases` now deletes canonical alias rows when SQL is configured.
- Bulk preview/confirmation binding remains enforced before mutation: actor, operation, preview ID, hash, expiry, and item scope must match.
- The v3 bulk apply API uses the SQL bulk path when `api.Server.AuditDB` is configured and records durable audit events through `audit.SQLWriter`.

Historical limit at this slice: live Mailu import compatibility was still open here. The Mailu live export/password preservation section above repaired that configured-path gap.

Verification:

- `go test -count=1 ./internal/ops` passed with SQL canonical mailbox disable and alias delete coverage plus durable audit readback.
- `go test -count=1 ./internal/api` passed with the bulk API mutating SQL mailbox state and writing SQL audit events.
