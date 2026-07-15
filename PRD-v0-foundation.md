# GopherMailForge PRD — v0 Foundation

## Goal

v0 establishes the containerized control-plane foundation. It must ship a testable base that can own state, render configuration, enforce permissions, audit mutations, define plugin boundaries, and bootstrap the required Authentik-adjacent identity service without pretending the mail stack is complete.

## Scope

### v0.1 Repo + project skeleton

- Go module and repository structure.
- Dockerfile for the GopherMailForge control-plane container.
- Docker Compose development/reference skeleton.
- GOTTH layout: Go handlers, templ components, Tailwind pipeline, HTMX conventions.
- Service-layer boundaries for config, persistence, auth, audit, permissions, plugins, and rendering.
- Migration framework.
- Unit/contract test harness skeleton.

### v0.2 Data model + migrations

- Domains.
- Users/mailboxes.
- Aliases.
- Relays.
- Tokens and app-password/mail-client token primitives.
- Authentik/OIDC identity references.
- Domain-manager/scoped-access references.
- Audit log schema.
- Generated-config state metadata.
- Migration history table.

### v0.3 Typed config + render/apply gate

- Typed config file format and parser.
- Validation before render.
- Generated config output directory.
- Config diff preview.
- Explicit apply gate.
- Audit event for render/apply.
- Generated files visibly marked as generated.
- Operator override paths declared explicitly.

### v0.4 Required Authentik base

- Required Authentik service/profile in Compose.
- OIDC config skeleton.
- SCIM config skeleton.
- Required group/role mapping model for:
  - global admins
  - domain managers
  - scoped domain access
- Bootstrap/recovery boundaries that do not depend on Authentik being healthy.
- Authentik remains adjacent; it is never embedded.

### v0.5 Audit + permission core

- Audit writer.
- Redaction rules.
- Actor/action/resource model.
- Permission simulator core.
- Break-glass local admin path.
- Audit every v0 mutation.
- Required audit fields:
  - event ID
  - timestamp
  - actor type
  - actor ID
  - source IP/user-agent when applicable
  - action
  - resource type
  - resource ID
  - redacted before/after summary
  - request/correlation ID
  - result
  - error code when failed

### v0.6 Admin UI shell

- GOTTH admin shell.
- Login/session shell.
- Dashboard/status page.
- Read-only config/status views.
- Authentik/bootstrap status page.
- UI mutations must go through the same service/auth/audit path as API and CLI.

### v0.7 Plugin runtime foundation

- Plugin registry model.
- Protobuf contract layout.
- gRPC server/client skeleton.
- Plugin service identity model.
- Health/version/capability RPCs.
- Deadlines, request IDs, structured errors.
- No in-process plugin loading.
- Plugin containers only.
- No Docker socket access.
- No broad filesystem mounts.
- Plugin failure cannot corrupt core state.

### v0.8 Plugin seam definitions

Define interfaces only; do not build a plugin zoo:

1. Webmail provider.
2. DNS provider integration.
3. ACME/certificate backend.
4. Backup storage backend.
5. Notification backend.
6. Import source.

Core owns policy. Plugins provide mechanisms.

### v0.9 TLS config model

- TLS modes:
  - manual certificates
  - Let’s Encrypt
  - dev/internal/self-signed only when explicitly non-production
- Validate hostnames.
- Validate cert paths.
- Validate public URL consistency.
- Validate Authentik/OIDC redirect URL consistency.
- No production silent fallback to self-signed certs.

## Non-goals

- No Postfix/Dovecot/Rspamd production contract yet.
- No SCIM implementation yet.
- No real OIDC login flow yet beyond config/model skeleton.
- No plugin implementations beyond stubs/contracts.
- No custom webmail.

## Acceptance criteria

- Control plane builds as a Docker container.
- Compose skeleton starts the control plane and required base dependencies.
- Migrations run against an empty database.
- Typed config validates and renders deterministic output.
- Render/apply requires explicit apply and emits an audit event.
- Audit writer records redacted mutation events.
- Permission simulator can explain simple allow/deny results.
- Authentik service/profile exists in the deployment topology and has modeled OIDC/SCIM/role-mapping config.
- Plugin gRPC health/version/capability contracts compile and are testable.
- No plugin can run in-process.
- `git diff --check` and relevant Go tests pass.
