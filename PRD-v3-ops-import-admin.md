# GopherMailForge PRD — v3 Ops + Import + Mature Admin

## Goal

v3 turns the working mail system into an operationally serious system: audit visibility, verified backups, snapshot/rollback guidance, Mailu import, abuse/rate-limit dashboards, and mature admin workflows.

## Scope

### v3.1 Audit UI

- Audit viewer.
- Filtering/search.
- Export.
- Retention tooling.
- Actor/resource/action filtering.
- Redaction remains enforced.
- Audit capture already exists from v0; v3 is the UI/search/export layer.

### v3.2 Backup/restore verification

- Backup capture.
- Backup storage plugin read/write.
- Restore into temporary DB/container.
- Schema check.
- Daemon contract tests against restored data.
- Mark backup verified only after restore validation passes.
- Failure reports must be actionable.

### v3.3 Snapshot/rollback UI

- Snapshot browser.
- Config diff viewer.
- Migration/image/plugin-version display.
- Rollback guidance.
- Verified restore status.
- No fake rollback promises for destructive migrations without verified backup.

### v3.4 Import source plugin: Mailu

- Mailu import plugin container.
- Parse supported Mailu state:
  - domains
  - users
  - aliases
  - relays
  - DKIM keys
  - compatible tokens where safe
- Import report:
  - imported
  - skipped
  - incompatible
  - manual action required
- Core validates/adopts state.
- Contract-test verification before declaring import successful.
- Import parsing is pluggable; state admission is core.

### v3.5 Abuse/rate-limit dashboard

- Auth failures.
- Sender limits.
- Rejected recipients.
- Spam decisions.
- Suspicious outbound volume.
- Queue/deferred-mail correlation.

### v3.6 Admin UI polish

- Complete workflows.
- Bulk operations only where safe.
- Better diagnostics display.
- Config diff viewer.
- Mail flow trace UI.
- Permission simulator UI.
- Generated config status/config surfaces for plugin-backed mechanisms.

## Non-goals

- No custom webmail.
- No broad plugin ecosystem.
- No hidden destructive bulk operations.
- No import that silently weakens passwords, DKIM permissions, role mappings, or daemon lookup behavior.

## Acceptance criteria

- Audit UI can answer who changed what, when, through which path, and with what result.
- Backup verification restores into an isolated environment and proves schema/contract validity.
- Snapshot UI shows generated config, migration version, image versions, plugin versions, and deployment policy.
- Mailu import can move supported state without silent data loss or behavior weakening.
- Abuse/rate-limit dashboard exposes operationally useful signals.
- Admin UI covers the common operational workflows without bypassing API/service/audit paths.
