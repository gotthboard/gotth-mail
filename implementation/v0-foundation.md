# Implementation Spec — v0 Foundation

Source PRD: [PRD-v0-foundation.md](../PRD-v0-foundation.md)
Source architecture: [architecture/v0-foundation.md](../architecture/v0-foundation.md)

## Goal

Build the minimal Go control-plane foundation: container, Compose skeleton, typed config, migrations, audit, authorization, render/apply gate, Authentik base model, GOTTH shell, plugin contract skeleton, and TLS config validation.

v0 must not implement production Postfix/Dovecot/Rspamd behavior or pretend the mail stack is complete.

## Source layout

Required packages:

```text
cmd/gophermailforge
cmd/gmf
internal/api
internal/apply
internal/audit
internal/authn
internal/authz
internal/config
internal/httpui
internal/plugin
internal/render
internal/store
internal/version
proto/gophermailforge/plugin/v1
compose/reference
migrations
test/contract
```

`cmd/gophermailforge` starts HTTP, migrations if configured, health, and plugin client runtime.
`cmd/gmf` exposes config validation, migration, render, diff, apply, and permission-simulator commands.

## Database schema

Initial tables:

### `schema_migrations`

- `version` text primary key
- `applied_at` timestamp not null
- `checksum` text not null
- `dirty` boolean not null default false

### `domains`

- `id` uuid primary key
- `name` text not null unique, lower-case normalized
- `enabled` boolean not null default true
- `created_at`, `updated_at`

Validation:

- domain name must be syntactically valid DNS name
- no silent case-sensitive duplicates

### `mailboxes`

- `id` uuid primary key
- `domain_id` uuid references `domains(id)`
- `local_part` text not null
- `display_name` text
- `enabled` boolean not null default true
- `quota_bytes` bigint null
- `created_at`, `updated_at`
- unique `(domain_id, local_part)`

### `aliases`

- `id` uuid primary key
- `domain_id` uuid references `domains(id)`
- `local_part` text not null
- `targets_json` json/text not null
- `enabled` boolean not null default true
- `created_at`, `updated_at`
- unique `(domain_id, local_part)`

### `relays`

- `id` uuid primary key
- `domain_id` uuid references `domains(id)` null for global relay
- `name` text not null
- `target` text not null
- `enabled` boolean not null default true
- `created_at`, `updated_at`

### `tokens`

- `id` uuid primary key
- `subject_type` text not null
- `subject_id` text not null
- `kind` text not null enum: `api`, `app_password`, `plugin_service`, `scim_client`, `break_glass`
- `verifier` text not null
- `label` text not null
- `scope_json` json/text not null
- `created_at`, `last_used_at`, `revoked_at`

Never store plaintext token/app-password values.

### `identity_refs`

- `id` uuid primary key
- `provider` text not null enum: `authentik`, `local`
- `subject` text not null
- `mailbox_id` uuid null references `mailboxes(id)`
- `created_at`, `updated_at`
- unique `(provider, subject)`

### `role_bindings`

- `id` uuid primary key
- `identity_ref_id` uuid references `identity_refs(id)`
- `role` text not null enum: `global_admin`, `domain_manager`, `scoped_domain_access`
- `domain_id` uuid null references `domains(id)`
- `created_at`, `updated_at`

### `audit_events`

- fields required by [IMPLEMENTATION.md](../IMPLEMENTATION.md#audit-contract)
- `before_redacted_json` json/text null
- `after_redacted_json` json/text null
- immutable after insert

### `generated_config_sets`

- `id` uuid primary key
- `status` text enum: `staged`, `applied`, `superseded`, `failed`
- `input_config_hash` text not null
- `db_state_hash` text not null
- `deployment_policy_hash` text not null
- `output_path` text not null
- `diff_summary_json` json/text null
- `created_by_actor` text not null
- `created_at`, `applied_at`

### `plugin_registrations`

- `id` uuid primary key
- `name` text not null unique
- `seam` text not null enum: `webmail`, `dns`, `acme`, `backup`, `notification`, `import`
- `image` text not null
- `endpoint` text not null
- `service_identity_token_id` uuid references `tokens(id)`
- `enabled` boolean not null default true
- `created_at`, `updated_at`

## Typed config

Initial config file format: YAML or TOML, chosen once before implementation. The parser must reject unknown top-level sections unless a section is explicitly marked experimental.

Required sections:

```yaml
server:
  public_url: "https://mail.example.test"
  listen: ":8080"
database:
  dsn: "postgres://..."
tls:
  mode: "manual|letsencrypt|dev_self_signed"
  cert_path: "optional"
  key_path: "optional"
authentik:
  enabled: true
  base_url: "https://auth.example.test"
  oidc_client_id: "..."
  scim_base_url: "..."
roles:
  global_admin_group: "..."
  domain_manager_group: "..."
  scoped_domain_group_prefix: "..."
render:
  staging_dir: "./var/generated/staged"
  applied_dir: "./var/generated/applied"
plugins:
  - name: "stub-dns"
    seam: "dns"
    image: "..."
    endpoint: "dns-plugin:9443"
```

Validation rules:

- production cannot use `dev_self_signed`
- `public_url` host must match configured TLS and Authentik/OIDC redirect host expectations
- manual TLS requires cert/key path presence
- plugin seam values must be from the allowed seam enum
- generated config output directories must not overlap operator override paths

## Render/apply state machine

```text
unrendered -> staged -> applied
                 |-> superseded
                 |-> failed
```

Rules:

- render validates config before writing staged output
- staged output is written to a new content-addressed directory
- generated files include a header marking them generated
- diff compares staged output to current applied output
- apply requires explicit actor confirmation
- apply writes audit event
- editing generated files directly is unsupported; overrides must live in configured override paths

CLI commands:

```text
gmf config validate --config <path>
gmf render --config <path>
gmf diff --config <path>
gmf apply --config <path> --confirm <staged-id>
```

## HTTP/API shell

Minimum endpoints:

```text
GET  /healthz
GET  /readyz
GET  /api/v1/status
GET  /api/v1/config/effective
POST /api/v1/config/render
GET  /api/v1/config/render/{id}/diff
POST /api/v1/config/render/{id}/apply
GET  /api/v1/audit/events
POST /api/v1/authz/explain
GET  /api/v1/plugins
GET  /api/v1/plugins/{id}/health
```

Mutation endpoints must run: authenticate -> authorize -> validate -> mutate/apply -> audit.

## Audit implementation

Audit writer API:

```go
type Event struct {
    ID string
    Time time.Time
    Actor ActorRef
    Source *RequestSource
    Action string
    Resource ResourceRef
    BeforeRedacted any
    AfterRedacted any
    CorrelationID string
    Result string
    ErrorCode string
}
```

Redaction tests must prove passwords, tokens, private keys, client secrets, and raw app-password values do not appear in persisted events.

## Authorization implementation

Core interface:

```go
type Authorizer interface {
    Decide(ctx context.Context, actor Actor, action Action, resource Resource) (Decision, error)
    Explain(ctx context.Context, actor Actor, action Action, resource Resource) (Explanation, error)
}
```

Initial policy:

- local admin can administer all resources
- break-glass actor can perform bootstrap/recovery actions only
- API tokens are limited by stored scopes
- plugin service actors cannot mutate core policy or grant roles
- OIDC/SCIM actors exist as placeholders until v2 behavior is implemented

## Authentik base

v0 stores Authentik config and role mapping model. It does not perform full OIDC login or SCIM provisioning.

Bootstrap/recovery must work when Authentik is unavailable through local admin or break-glass paths.

## Plugin protobuf skeleton

Package: `gophermailforge.plugin.v1`

```proto
service PluginControl {
  rpc Health(HealthRequest) returns (HealthResponse);
  rpc Version(VersionRequest) returns (VersionResponse);
  rpc Capabilities(CapabilitiesRequest) returns (CapabilitiesResponse);
}
```

Every request includes:

- correlation ID metadata
- authenticated service identity metadata
- deadline

Failure behavior:

- unauthenticated -> `UNAUTHENTICATED`
- authenticated but disabled registration -> `PERMISSION_DENIED`
- deadline exceeded -> `DEADLINE_EXCEEDED`
- malformed capability response -> plugin marked unhealthy, core state unchanged

No plugin may be loaded in-process.

## GOTTH shell

Minimum pages:

- login/session shell
- dashboard/status
- read-only config/effective config
- render/diff/apply shell
- audit event list
- permission simulator form
- Authentik/bootstrap status
- plugin status list

HTMX actions call the same API/service path as CLI/API mutations.

## Verification

Required tests:

- container build smoke test
- migrations on empty DB
- config parser rejects invalid/unknown production-dangerous config
- render output deterministic for same input
- diff/apply emits audit event
- redaction tests for audit writer
- authorization explain tests for local admin, break-glass, API token, plugin service
- plugin health/version/capability authenticated success
- unauthenticated plugin gRPC rejection
- plugin failure cannot corrupt core state
- `git diff --check`
- `go test ./...`
