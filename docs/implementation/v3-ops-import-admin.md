# Implementation Spec — v3 Ops + Import + Mature Admin

Source PRD: [PRD-v3-ops-import-admin.md](../prd/PRD-v3-ops-import-admin.md)
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
gotth-mailctl audit retention preview --policy <policy>
gotth-mailctl audit retention apply --policy <policy> --confirm <preview-id>
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

Token/app-password import is allowed only for v2-supported Authentik/Django `pbkdf2_sha256` verifier, non-plaintext records whose hash/verifier algorithm, parameters, scope, and revocation state can be preserved. Anything else is `incompatible` or `manual_action_required`.

Live Mailu user-password import uses Mailu `config-export --secrets --json` data. Mailu Passlib `bcrypt-sha256` password hashes must be preserved as `mailu_bcrypt_sha256$<original-mailu-passlib-hash>` for Authentik custom-hasher migration compatibility. They must not be presented as Django `bcrypt_sha256`, and redacted non-secret exports are rejected for user password preservation. Applying an import may adopt those mailbox records for routing/recipient state, but local Dovecot secret verification remains limited to verifier algorithms implemented by GOTTH Mail.

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

Apply requires explicit confirmation using preview ID/hash, source fingerprint, actor binding, and expiry. Stale previews, changed source fingerprints, mismatched actors, or mismatched preview hashes are rejected.

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

## Extensions administrator

Host-owned routes:

```text
GET  /admin/extensions
GET  /admin/extensions/{instance-id}
POST /api/v1/extensions/{instance-id}/configure/preview
POST /api/v1/extensions/{instance-id}/configure/apply
POST /api/v1/extensions/{instance-id}/test
POST /api/v1/extensions/{instance-id}/enable
POST /api/v1/extensions/{instance-id}/disable
POST /api/v1/extensions/{instance-id}/update/preview
POST /api/v1/extensions/{instance-id}/update/apply
POST /api/v1/extensions/{instance-id}/rollback
POST /api/v1/extensions/{instance-id}/uninstall/preview
POST /api/v1/extensions/{instance-id}/uninstall/apply
```

The HTML surface is server-rendered Go + templ + Tailwind with HTMX fragments
and ordinary form fallback. Every POST requires administrator authorization,
CSRF, bounded input, and the same service-layer confirmation/audit contract as
the API. Sensitive reconfiguration, capability expansion, rollback, uninstall,
and secret deletion require recent reauthentication or the product's admitted
equivalent high-risk confirmation.

The registry stores instance ID, extension/repository identity, immutable
artifact and rollback pins, manifest/configuration/grant/session digests,
lifecycle and health codes, enabled state, timestamps, and audit correlation.
Secret values live only in a Mail-owned encrypted installation secret store
that this feature must define and verify before the first extension can be
enabled; projections contain slot IDs and configured/rotated status only.

Configuration metadata admits only a closed set of bounded scalar field kinds,
labels, validation constraints, defaults, and named secret slots. It admits no
markup, script, style, template, executable expression, redirect, arbitrary
action, or secret value. Provider-specific complexity is implemented by a
reviewed Mail adapter.

Enable ordering is validate pin and metadata, persist configuration, inject
scoped secrets, authenticate transport, negotiate grant, start, handshake,
health, then admit routing. Disable ordering is revoke grant, remove routing,
stop, then record final state. Retried and ambiguous operations reconcile by
the bound configuration/session identities rather than guessing success.

Production runtime is enabled only when all three protected settings exist:

```text
GOTTH_MAIL_EXTENSION_MASTER_KEY_FILE
GOTTH_MAIL_EXTENSION_ARTIFACT_ROOT
GOTTH_MAIL_EXTENSION_RUNTIME_ROOT
```

The artifact root contains one directory per lowercase `sha256:<hex>` pin,
named by the hex portion. Each directory contains an immutable
`gotth-extension-webhook` executable and an `artifact-pin` file containing the
exact full pin. Directories and executables may not be symlinks or
group/world-writable. The runtime root is an owner-only non-symlink directory.

For every start Mail writes mode-0600 configuration, runtime-binding,
service-token, and `webhook.hmac-key` files below a new mode-0700 instance
directory. The child receives only those paths and the Unix-socket path in a
bounded environment. Mail verifies challenge echo, extension identity,
release version, control/interface versions, manifest/grant/session digests,
capabilities, and health before routing. Stop failure leaves the runtime record
and protected directory intact for reconciliation; it never reports success
while a process may remain alive.

The managed webhook route and a statically configured notification plugin are
mutually exclusive. Startup rejects that ambiguous configuration instead of
silently changing which backend receives alerts. The webhook adapter supports
alerts only; prompts and Telegram command/approval behavior are absent.

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
- import apply requires preview hash/source fingerprint/actor binding/expiry confirmation and audits mutations
- abuse/rate-limit dashboard exposes required operational signals without hidden policy
- admin workflows do not bypass API/service/auth/audit paths
- bulk operations prove preview, confirmation, per-item result reporting, and per-item or grouped audit entries
- list/detail projections are complete, bounded, and secret-free
- hostile configuration metadata cannot inject HTML/script/style/actions or
  broaden grants
- write-only secret create/rotate/delete never redisplays or logs values
- setup and test cannot enable an unhealthy or unauthenticated instance
- disable blocks new routing before shutdown and is safe to retry
- update previews bind actor, artifact, manifest, grant, configuration, expiry,
  and privilege diff; stale or changed previews fail closed
- prior pin rollback works without changing unrelated extensions
- keyboard, focus, status announcement, 320-pixel reflow, theme contrast, and
  ordinary HTML/no-JavaScript flows pass
- Mail cannot enumerate or mutate another product's registry or secrets
- `git diff --check`
- `go test ./...`
