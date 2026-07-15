# Implementation Spec — v3 Ops + Import + Mature Admin

Source PRD: [PRD-v3-ops-import-admin.md](../PRD-v3-ops-import-admin.md)
Source architecture: [architecture/v3-ops-import-admin.md](../architecture/v3-ops-import-admin.md)

## Goal

Add serious operator surfaces: audit UI/search/export, verified backup/restore, snapshot/rollback guidance, Mailu import plugin, abuse/rate-limit dashboard, and mature admin workflows.

## Audit UI/search/export

API:

```text
GET /api/v1/audit/events
GET /api/v1/audit/events/{id}
GET /api/v1/audit/export?format=jsonl|csv
```

Query filters:

- time range
- actor type/id
- action
- resource type/id
- result
- correlation ID
- error code

Export preserves redaction. UI must not expose secrets or unredacted before/after values.

Retention tooling:

```text
gmf audit retention preview --policy <policy>
gmf audit retention apply --policy <policy> --confirm <preview-id>
```

Retention apply is a mutation and must be audited.

## Backup/restore verification

Backup state table:

- `id`
- `plugin_registration_id`
- `status`: `captured`, `verify_running`, `verified`, `failed`
- `artifact_ref`
- `schema_version`
- `config_set_id`
- `created_at`
- `verified_at`
- `failure_report_json`

Flow:

1. capture backup through backup storage plugin
2. restore into isolated temporary DB/container
3. run schema check
4. run daemon contract tests against restored data
5. mark verified only after all validation passes
6. emit actionable failure report on any failure

Core owns verification, failure reporting, and verified status. Plugin owns storage mechanism only.

Failure report includes failed step, safe error, remediation hint, correlation ID, and whether retry may help.

## Snapshot/rollback UI

Snapshot API:

```text
GET /api/v1/snapshots
GET /api/v1/snapshots/{id}
GET /api/v1/snapshots/{id}/diff?against=<id>
```

Snapshot fields:

- generated config set ID/hash
- migration version
- image versions
- plugin versions
- deployment policy hash
- verified restore status

Rollback UI provides guidance. It must not present a destructive rollback as safe unless a verified backup exists.

## Mailu import plugin

Plugin seam: `import`.

Mailu import plugin responsibilities:

- parse Mailu source state
- classify source items
- report parse failures
- return candidate records

Core responsibilities:

- validate candidates
- decide admission
- validate/adopt state into canonical DB
- audit import mutations
- run daemon contract verification before declaring success

Import candidate types:

- domains
- users/mailboxes
- aliases
- relays
- DKIM keys
- compatible tokens where safe

Import report item status:

```text
imported
skipped
incompatible
manual_action_required
failed_validation
```

No import may silently weaken passwords, DKIM permissions, role mappings, or daemon lookup behavior.

API:

```text
POST /api/v1/imports/mailu/preview
POST /api/v1/imports/mailu/apply
GET  /api/v1/imports/{id}
```

Apply requires explicit confirmation using preview ID/hash.

## Abuse/rate-limit dashboard

Inputs:

- auth failure events
- sender limit events
- rejected recipient events
- spam decisions
- suspicious outbound volume metrics
- queue/deferred-mail correlation

Dashboard reads existing logs/metrics/state. It must not invent hidden policy.

API:

```text
GET /api/v1/ops/abuse-summary
GET /api/v1/ops/rate-limits
GET /api/v1/ops/deferred-correlation
```

## Mature admin workflows

Bulk operation pattern:

```text
preview -> explicit confirmation -> per-item execution -> per-item result report -> per-item or grouped audit entries
```

Bulk operation APIs include:

```text
POST /api/v1/bulk/<operation>/preview
POST /api/v1/bulk/<operation>/apply
GET  /api/v1/bulk/jobs/{id}
```

Apply must verify preview hash, actor, action, resource scope, and expiry. Stale previews are rejected.

UI polish must not create a second mutation path. GOTTH screens call API/service/auth/audit paths.

## Verification

Required tests:

- audit UI answers who changed what, when, through which path, and result
- audit filters and exports preserve redaction
- retention preview/apply requires confirmation and audit
- backup restore into isolated DB/container proves schema and daemon contract validity
- backup failure reports are actionable
- snapshot UI shows config/migration/image/plugin/deployment/verified-restore state
- rollback UI refuses fake safety claims without verified backup
- Mailu import preview/apply moves supported state without silent weakening
- import apply requires preview hash/confirmation and audits mutations
- abuse/rate-limit dashboard exposes required operational signals without hidden policy
- admin workflows do not bypass API/service/auth/audit paths
- bulk operations prove preview, confirmation, per-item result reporting, and per-item or grouped audit entries
- `git diff --check`
- `go test ./...`
