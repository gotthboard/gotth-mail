# GopherMailForge Implementation Specifications

## Purpose

This specification layer converts the PRDs and architecture documents into implementation contracts. It defines concrete schemas, APIs, state machines, generated artifacts, error behavior, and test contracts.

This is still not code. Implementation may begin only after a version has a PRD, architecture document, and implementation spec that agree on scope and verification.

## Source documents

- [Product PRD](../prd/PRD.md)
- [Architecture overview](../architecture/ARCHITECTURE.md)
- [v0 implementation spec](v0-foundation.md) — from [PRD-v0-foundation.md](../prd/PRD-v0-foundation.md) and [architecture/v0-foundation.md](../architecture/v0-foundation.md)
- [v1 implementation spec](v1-mail-core.md) — from [PRD-v1-mail-core.md](../prd/PRD-v1-mail-core.md) and [architecture/v1-mail-core.md](../architecture/v1-mail-core.md)
- [v2 implementation spec](v2-identity-provisioning.md) — from [PRD-v2-identity-provisioning.md](../prd/PRD-v2-identity-provisioning.md) and [architecture/v2-identity-provisioning.md](../architecture/v2-identity-provisioning.md)
- [v3 implementation spec](v3-ops-import-admin.md) — from [PRD-v3-ops-import-admin.md](../prd/PRD-v3-ops-import-admin.md) and [architecture/v3-ops-import-admin.md](../architecture/v3-ops-import-admin.md)
- [v4 implementation spec](v4-webmail.md) — from [PRD-v4-webmail.md](../prd/PRD-v4-webmail.md) and [architecture/v4-webmail.md](../architecture/v4-webmail.md)
- [v5 implementation spec](v5-notifications.md) — from [PRD-v5-notifications.md](../prd/PRD-v5-notifications.md) and [architecture/v5-notifications.md](../architecture/v5-notifications.md)

## Global implementation rules

### Language and runtime

- Primary implementation language: Go.
- Deployment target: Docker/Compose first.
- Admin UI: Go handlers + templ + Tailwind + HTMX.
- No React/Vue/Svelte SPA framework in the admin UI.
- Plugins are separate Docker containers using gRPC/protobuf.
- The control plane remains the sole authority for policy, validation, state admission, mutation, and audit.

### Change history

Every meaningful repository change must update [docs/CHANGELOG.md](../CHANGELOG.md) in the same commit. This includes product docs, architecture, implementation specs, workflow state, source code, tests, deployment behavior, security posture, and user-visible behavior.

Each changelog entry must include date/time with timezone, commit identifier, affected files, verbose explanation, and verification performed. Historical entries use real commit hashes. The entry for the commit currently being created may use `current commit; hash assigned by Git after commit` because Git commit hashes include the changelog content itself.

The changelog does not replace workflow evidence, test results, or handoff notes. It is the compact chronological index of what changed.

### Repository layout

Initial source layout should be:

```text
cmd/
  gophermailforge/     # server entrypoint
  gmf/                 # CLI entrypoint
internal/
  api/                 # versioned REST/JSON API handlers
  apply/               # render/diff/apply gate
  audit/               # audit writer, redaction, query model
  authn/               # sessions, local admin, OIDC integration when added
  authz/               # actor/action/resource decisions
  config/              # typed config parser/validator
  daemon/              # internal daemon API contracts
  diag/                # doctor, lookup debugger, traces
  httpui/              # GOTTH admin UI
  plugin/              # plugin registry, gRPC clients, service identity
  render/              # generated config renderers
  store/               # persistence and migrations
  version/             # build/version metadata
proto/
  gophermailforge/     # protobuf contracts
web/
  templates/           # templ components
  static/              # generated CSS/static assets
compose/
  reference/           # reference Docker Compose topology
migrations/
test/
  contract/
  integration/
  fixtures/
```

Do not invent package layers until an interface boundary exists. Handlers call services. Services own validation, authorization, mutation, and audit calls.

### API conventions

- External API: versioned JSON under `/api/v1/`.
- Internal daemon APIs: versioned and documented separately from external APIs.
- Plugin APIs: protobuf contracts, semver-capability reported by plugin health/version/capability RPCs.
- Every request receives or creates a correlation ID.
- Every mutation has an actor, action, resource, validation phase, authorization phase, apply phase, and audit result.

Standard error envelope:

```json
{
  "error": {
    "code": "string_enum",
    "message": "human safe summary",
    "field": "optional.field.path",
    "correlation_id": "uuid-or-request-id",
    "retryable": false
  }
}
```

Messages must be safe for operators. Secrets, private keys, full tokens, passwords, and unredacted before/after values must never appear in API errors, UI errors, logs, audit exports, Telegram alerts, or plugin error payloads.

### State and migrations

- Relational database required.
- Migrations are ordered, repeatable only where explicitly marked, and recorded in `schema_migrations`.
- All tables use stable IDs, created/updated timestamps where useful, and explicit uniqueness constraints.
- Constraints belong in the database where possible; boundary validation still happens before writes.
- Generated daemon config is reproducible from typed config + database state + selected deployment policy.

### Audit contract

Every mutation writes one audit event or an explicit failed-attempt event.

Minimum audit fields:

- event ID
- timestamp
- actor type
- actor ID
- source IP/user-agent when applicable
- action
- resource type
- resource ID
- redacted before summary
- redacted after summary
- request/correlation ID
- result
- error code when failed

Audit writes must not be optional for mutation paths. If the primary audit write fails, the mutation must fail closed. The only exception is an explicitly classified emergency break-glass operation that writes a durable local recovery audit record to a configured fallback sink before or atomically with the mutation; if that fallback write fails, the break-glass mutation also fails closed.

### Authorization contract

Authorization uses actor/action/resource decisions. UI, API, CLI, Telegram, SCIM, OIDC-backed sessions, and plugin-mediated mechanisms must not bypass the same decision path.

Actors:

- `local_admin`
- `api_token`
- `oidc_subject`
- `scim_client`
- `system`
- `break_glass`
- `plugin_service`
- `telegram_actor` when v5 is enabled

Plugin service identity authenticates a plugin. It does not grant user/admin permissions.


### Password verifier compatibility

Mailbox-password and mail-client verifier storage must use Authentik-compatible Django encoded password-hash strings where password sync or Dovecot verification is intended. The encoded string must carry the algorithm identifier and parameters, and must be accepted by Authentik/Django `identify_hasher`.

GopherMailForge must not invent a private mail-only password hash. New password hashes use the configured Authentik-compatible hasher profile. Imports accept only recognized Django encoded hashes unless an explicit migration exception is recorded. Plaintext import/export is forbidden. See [Authentik password hashing compatibility](../reference/authentik-password-hashing.md).

### Exact sender OpenPGP/MIME contract

Outbound email implementation must conform to [Exact Sender Identity Binding for OpenPGP/MIME Signed Email](../reference/openpgp-exact-sender/draft-hunn-openpgp-exact-sender-signatures-01.md). Implemented operational capabilities for temporal identity state, address/name history, search/audit indexing, downgrade detection, key-rotation continuity, and forensic export must conform to [Operational Identity History and Audit Indexing for Exact Sender Binding](../reference/openpgp-exact-sender/draft-hunn-exact-sender-operational-identity-history-00.md).

Implementation requirements:

- OpenPGP/MIME signing is required for newly sent outbound email.
- DKIM is domain/server proof and does not satisfy exact sender identity binding.
- The signing fingerprint must resolve to exactly one active configured sender identity.
- The resolved sender identity must be authorized to assert the message `From` and `Sender` fields.
- Explicit delegated sending must be recorded and auditable.
- Missing, unmapped, ambiguous, revoked, expired, disabled, mismatched, or unauthorized signing state fails closed.
- No implementation may preserve delivery convenience by falling back to unsigned mail.

### Plugin contract

All plugins must:

- run out of process as Docker containers
- use gRPC/protobuf on the internal deployment network
- authenticate with service identity credentials
- expose health/version/capability RPCs
- use request/correlation IDs
- use deadlines
- return structured errors
- avoid Docker socket access
- avoid broad filesystem mounts
- fail without corrupting core state

Core owns policy. Plugins provide mechanisms.

### Verification contract

Every version spec must define:

- unit tests for pure validation and state transitions
- database migration tests on empty DB and upgraded DB where relevant
- contract tests for daemon/plugin/API boundaries
- negative tests for malformed input and unauthorized actions
- integration tests for the reference Compose topology when the feature requires containers
- `git diff --check`
- relevant Go tests

A green build without tests for the touched behavior is not evidence.
