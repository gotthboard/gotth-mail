# GOTTH Mail PRD — v3 Ops + Import + Mature Admin

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
- Bulk operations only with dry-run/preview, explicit confirmation, per-item result reporting, and per-item or grouped audit entries.
- Better diagnostics display.
- Config diff viewer.
- Mail flow trace UI.
- Permission simulator UI.
- Generated config status/config surfaces for plugin-backed mechanisms.

### v3.7 Extensions administrator

- The Extensions inventory makes every installed extension reachable through
  ordinary paginated HTML navigation, with repository, pinned
  version/artifact, manifest digest, granted permissions, lifecycle, health,
  enabled state, available update, and rollback pin.
- A detail surface provides Overview, Configuration, Secrets, Permissions,
  Health, Audit, Versions, and Rollback without exposing secret values.
- Setup is preview, exact grant approval, configuration, write-only secret
  entry, bounded connection test, then enable after authenticated handshake and
  health success.
- Disable revokes the grant and blocks new calls before process shutdown while
  preserving configuration. Uninstall and secret deletion are separate
  confirmed operations.
- Updates preview artifact, manifest, interface, capability, field, and secret-
  slot changes and retain the prior admissible pin for rollback.
- The server renders the page using Go, templ, Tailwind, and HTMX with ordinary
  HTML fallback. Extensions supply no executable presentation.

### HTML inventory pagination decision (2026-10-02; contracts only)

Owner decision40028 approves pagination and isolation of malformed OFF-PAGE
records for the HTML administrator inventory. This is new visible product
behavior, not renderer cleanup. Implementation remains pending review.

- A fixed projection of at most50 instances per page replaces the all-at-once
  HTML list. This is not an installation quota, configurable registry limit,
  per-instance byte/field/grant limit, or change to the legacy JSON API.
- Preserve ascending extension-ID ordering. On a stable valid dataset, following
  First/Next must reach every entry, without omission/duplication. The schema's
  unique (product, extension_id) key makes this a total order within Mail;
  duplicate IDs are rejected by that existing constraint, not hidden by paging.
- A malformed record outside the selected page, INCLUDING the lookahead entry,
  must not be decoded or have secret status loaded for this page. Selected rows
  retain the complete existing decoding/status error behavior: no skipped bad
  rows, partial success, or reduced-column escape from metadata/config errors.
- Ordinary links work with JavaScript disabled. First/Next, browser Back/Forward,
  theme changes and refresh preserve the documented page position. No numbered
  pages, total count, Previous-query machinery, return URL or new browser storage.
- Cursor navigation is a live view, not a multi-request snapshot: concurrent
  changes can alter membership and require restarting at First. Empty/stale/end
  positions must not falsely claim that the whole registry is empty.
- Authentication precedes pagination parsing. Invalid bounded cursor/query input
  produces sanitized400; selected read/render failures retain existing500 and
  buffering semantics. Authorization/503/header precedence stays unchanged.
- Service.List and all non-HTML consumers remain unlimited with their existing
  behavior. Detail/recovery, authority, confirmation, schema and grant caps are
  unchanged. No new quota or migration is authorized by this decision.

## Non-goals

- No custom webmail.
- No broad plugin ecosystem.
- No hidden destructive bulk operations.
- No bulk mutation without preview, explicit confirmation, result reporting, and audit coverage.
- No import that silently weakens passwords, DKIM permissions, role mappings, or daemon lookup behavior.
- No extension-provided HTML, JavaScript, CSS, template, redirect, or arbitrary
  form action.
- No global administrator that can enumerate or mutate another GOTTH product's
  registry, grants, secrets, or audit state.

## Acceptance criteria

- Audit UI can answer who changed what, when, through which path, and with what result.
- Backup verification restores into an isolated environment and proves schema/contract validity.
- Snapshot UI shows generated config, migration version, image versions, plugin versions, and deployment policy.
- Mailu import can move supported state without silent data loss or behavior weakening.
- Abuse/rate-limit dashboard exposes operationally useful signals.
- Admin UI covers the common operational workflows without bypassing API/service/audit paths.
- Bulk operations prove preview, explicit confirmation, per-item result reporting, and audit coverage.
- The Extensions administrator proves setup, test, enable, disable, update,
  rollback, health, redaction, keyboard, responsive, and no-JavaScript flows
  against at least one real `gotth-extension-<slug>` artifact.

### Invalid stored metadata recovery (approved 2026-10-01)

Decodable but semantically invalid configuration metadata must not render normal
configuration fields. Return an explicit complete recovery-only detail document
(HTTP200), preserving Disable, confirmed all-secret deletion/uninstall, rollback,
and already-issued update Apply. Withhold Test, Enable/revalidate, configuration,
and new update preview. Existing authorization, CSRF and service confirmation/state
checks remain authoritative. Undecodable rows retain their existing error status;
this is not a universal corrupted-row repair facility. No automatic repair/activation.

## Read-only Permissions pagination MVP (owner40081; 2026-10-03)

Approved scope is the smaller proposal40080, not the broader40077 reply target.
Contracts only here; implementation and admission remain pending parent review.
Current performance tradeoffs are provisionally accepted by owner40075, not newly
proved cost bounds. The held1152-cell O/N/C study must not restart for this slice.

- **PERM-01 Inventory:** replace the three expanded permission-name lists with
  capability, interface and granted-secret-slot-name counts (including zero) and
  one ordinary **View permissions** link to the existing detail#permissions.
  Preserve other inventory fields, selected instances, errors and access policy.
- **PERM-02 One detail pager:** the read-only Permissions section displays at most
  **25 entries TOTAL**, not25 per category. Order is capabilities, interfaces,
  granted secret-slot names; preserve each stored list's order and every occurrence
  without sorting, filtering or deduplication. Label categories on every page.
  Empty/first/middle/last states and Previous/Next are ordinary HTML; every entry
  in an unchanged, metadata-valid detail grant set is reachable exactly once.
- **PERM-03 Navigation:** fixed size, native keyboard/no-JavaScript links, normalized
  theme and browser Back/Forward. It is a live view, not a frozen snapshot: edits
  between requests may move entries; reload/restart at page1 to traverse anew.
- **PERM-04 Admission:** bound GET query parsing and integer arithmetic; preserve
  route, authorization, service-nil and existing read/recovery error precedence.
  Malformed/duplicate/empty page values are sanitized400; valid beyond-end pages
  are sanitized404. Empty grants have one empty200 page. Exact grammar and limits
  are specified below in the implementation document, not a new grant quota.
- **PERM-05 Authority is untouched:** never page/truncate update form values,
  accepted-target payloads, preview diffs, confirmations or service inputs. No new
  route, permission subsystem, search/filter, per-row pager, JavaScript, storage,
  configurable limit, schema/API/edit/approval change or equipment acquisition.
- **PERM-06 Recovery and honest scope:** invalid-metadata detail remains recovery-
  only with its existing withheld surfaces; no permissions bypass/alternate route.
  Inventory counts still describe its loaded lists, and the ordinary detail link
  may reach recovery rather than expose names. This exception is explicit, not a
  claim that recovery now displays every grant. Undecodable rows still fail as before.

This is read-only readability, NOT whole-UI completion or a total HTML/DB/memory
bound. Full update inputs, complete approval diffs, configuration/secrets/status
surfaces, service.Get/selected inventory materialization and existing buffers remain
unchanged and potentially large. Do not claim this MVP fixes all grant-related cost.
Acceptance requires the finite tests, generation and one native navigation proof in
the feature plan plus independent final reviews; documents are not runtime evidence.

### PERM MVP implementation checkpoint (2026-10-03; review pending)

The approved read-only count/link and combined25-entry pager are implemented in
this working tree. Scoped PG16/17, race, generation and one real no-JavaScript
browser workflow now have successful evidence; independent final review and parent
admission remain pending. This is not whole-UI/beta completion, performance-bound
proof or an authorization to restart the held measurement study. All PERM-01..06
scope limits and the recovery-only exception above remain in force.
