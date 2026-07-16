# v3 ops/import/admin root completion evidence

Root feature: `v3.ops-import-admin`
Timestamp: 2026-07-16 12:45 CDT

## Completed children

- `v3.ops-import-admin.audit-backup-snapshots`
- `v3.ops-import-admin.mailu-import`
- `v3.ops-import-admin.abuse-bulk-ui`

## Root acceptance coverage

- Audit UI/API can answer actor/action/resource/result questions and export redacted JSONL/CSV.
- Retention apply requires preview confirmation and emits audit.
- Backup verification restores/validates schema and daemon contracts before marking verified, with actionable failure reports.
- Snapshot/rollback guidance refuses fake safety without verified restore status.
- Mailu import preview/apply rejects silent weakening, requires preview hash/source fingerprint/actor binding/expiry, and audits mutations.
- Abuse/rate-limit summary exposes required operational signals.
- Bulk admin workflows require preview, explicit confirmation, per-item results, and per-item audit.
- UI exposes audit, backup, snapshot, import, abuse, and bulk operator surfaces; backup/import/bulk forms execute service-backed preview/verify paths instead of dead/static links.

## Verification

- `git diff --check -- .` passed.
- `go test ./...` passed.

## Coverage gaps

No accepted v3 root coverage gap.
