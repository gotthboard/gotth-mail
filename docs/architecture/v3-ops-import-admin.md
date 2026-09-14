# Architecture — v3 Ops + Import + Mature Admin

Source PRD: [PRD-v3-ops-import-admin.md](../prd/PRD-v3-ops-import-admin.md)

## Goal

v3 adds operational maturity: audit UI, backup verification, snapshot/rollback guidance, Mailu import, abuse/rate-limit visibility, and mature admin workflows.

## Audit UI architecture

Audit capture exists from v0. v3 adds visibility:

- viewer
- filtering/search
- export
- retention tooling
- actor/resource/action filtering

Redaction remains enforced. UI must not expose secrets or unredacted before/after values.

## Backup/restore verification architecture

Backup verification flow:

1. capture backup through configured backup storage plugin
2. restore into temporary DB/container
3. run schema check
4. run daemon contract tests against restored data
5. mark backup verified only after validation passes
6. emit actionable failure report when any step fails

Storage mechanism is plugin-backed. Verification, failure reporting, and verified status are core-owned.

## Snapshot/rollback architecture

Snapshot UI shows:

- generated config
- migration version
- image versions
- plugin versions
- selected deployment policy
- verified restore status

Rollback UI provides guidance. It must not promise rollback for destructive migrations unless a verified backup exists.

## Mailu import architecture

Mailu import is the first import-source plugin.

Plugin responsibilities:

- parse Mailu source state
- report source items
- classify parse failures

Core responsibilities:

- validate imported state
- decide admission
- validate/adopt state into the canonical database
- write target state
- audit import mutations
- run contract verification

Supported imports where safe:

- domains
- users
- aliases
- relays
- DKIM keys
- compatible tokens

Import report includes:

- imported
- skipped
- incompatible
- manual action required

No import may silently weaken passwords, DKIM permissions, role mappings, or daemon lookup behavior.

## Abuse/rate-limit dashboard architecture

Dashboard surfaces:

- auth failures
- sender limits
- rejected recipients
- spam decisions
- suspicious outbound volume
- queue/deferred-mail correlation

It reads from existing logs/metrics/state; it must not invent hidden policy.

## Admin UI maturity

Adds:

- complete workflows
- config diff viewer
- mail flow trace UI
- permission simulator UI
- generated-config/plugin-backed status surfaces
- better diagnostics display
- bulk operations only with dry-run/preview, explicit confirmation, per-item result reporting, and per-item or grouped audit entries

Mature admin workflows call the same API/service/auth/audit paths as every other mutation surface. UI polish must not create a second mutation path.

## Extensions administrator architecture

The Extensions page is a GOTTH Mail control-plane view over a Mail-owned
registry. It is not a web surface served by extension processes.

```text
browser -> Mail admin routes -> authz/CSRF/confirmation
                              -> registry + encrypted secret store + audit
                              -> grant/routing/supervision adapter
                              -> authenticated out-of-process extension
```

The list and detail projections are secret-free. Constrained, versioned
configuration metadata is validated before Mail renders native templ
components. Unknown field kinds, duplicate names, over-limit documents,
executable presentation, arbitrary URLs/actions, and secret values fail
closed. Complex provider-specific workflows require reviewed Mail-owned
adapters rather than extension-injected UI.

Enable occurs only after the exact artifact, manifest digest, grant,
configuration revision, transport identity, handshake, and health result agree.
Disable first revokes the grant and removes the instance from new routing, then
stops it. Update is a separately confirmed privilege/configuration diff and
retains the previous pin. Every transition uses the existing service and audit
boundary and is idempotent or explicitly reconciled after ambiguity.

The page uses the separate administrator GUI's visual language and shares
reviewed design tokens with webmail, but it never gains webmail mailbox
authority. Mail and Board may present the same interaction pattern while
keeping separate registries and credentials.

## Verification gates

- audit UI answers who changed what, when, through which path, and result
- backup verification restores into isolated environment, proves schema/contract validity, and reports actionable failures
- snapshot UI shows config/migration/image/plugin/deployment state
- Mailu import moves supported state without silent weakening
- abuse/rate-limit dashboard exposes useful signals
- admin workflows do not bypass API/service/auth/audit paths
- bulk operations prove preview, confirmation, per-item result reporting, and per-item or grouped audit entries
- extension metadata cannot inject presentation or authority
- setup/test/enable/disable/update/rollback preserve grant, routing, secret,
  audit, accessibility, and failure-isolation boundaries
