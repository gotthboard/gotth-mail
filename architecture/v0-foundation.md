# Architecture — v0 Foundation

Source PRD: [PRD-v0-foundation.md](../PRD-v0-foundation.md)

## Goal

v0 builds the control-plane foundation. It must produce a containerized Go service that can own state, validate typed config, render deterministic output, audit mutations, enforce permissions, define plugin runtime contracts, and bootstrap the required Authentik-adjacent identity service.

v0 must not pretend the mail stack is complete.

## Container topology

Minimum v0 topology:

- `gophermailforge`: Go control-plane container
- database: development/reference database
- `authentik`: required identity service/profile skeleton
- plugin stub containers only where needed for gRPC contract tests

The control plane exposes:

- admin/API HTTP listener
- internal gRPC plugin client runtime
- health endpoint
- migration/config CLI entrypoints

## Go package boundaries

Suggested package boundaries:

- `cmd/gophermailforge` — server entrypoint
- `cmd/gmf` — CLI entrypoint
- `internal/config` — typed config parsing/validation
- `internal/store` — persistence and migrations
- `internal/audit` — audit writer/redaction
- `internal/authz` — actor/action/resource permission decisions
- `internal/render` — generated config rendering
- `internal/apply` — diff/apply gate
- `internal/plugin` — registry, identities, gRPC runtime
- `internal/httpui` — GOTTH admin shell
- `internal/api` — versioned API shell

Do not hide policy in handlers. Handlers call services; services write audit events.

## Data model foundation

v0 owns initial tables for:

- domains
- users/mailboxes
- aliases
- relays
- tokens/app-password primitives
- Authentik/OIDC identity references
- role/scoped-access references
- audit log
- generated-config metadata
- migration history
- plugin registry/service identities

Constraints belong in the database where possible. Validation also happens at boundaries.

## Typed config pipeline

Flow:

1. read typed config
2. validate config
3. normalize config
4. render generated files into staging output
5. compute diff against applied output
6. require explicit apply
7. write audit event

Generated files are owned by the control plane. Operator overrides live in explicit override paths, never by editing generated files.

## Audit architecture

Audit events are written by service-layer mutation paths, not by UI widgets.

Required event fields:

- event ID
- timestamp
- actor type and ID
- source IP/user-agent when applicable
- action
- resource type and ID
- redacted before/after summary
- request/correlation ID
- result
- error code when failed

Secrets are never logged.

## Permission architecture

Permissions use an actor/action/resource model.

Actors include:

- local admin
- API token
- OIDC subject placeholder
- SCIM client placeholder
- system actor
- break-glass actor

v0 includes a permission simulator core that can explain simple allow/deny decisions.

## Authentik foundation

v0 models the required Authentik service/profile and required mappings, but does not implement full OIDC login or SCIM provisioning.

The model must represent:

- OIDC client settings
- SCIM provider settings
- global-admin mapping
- domain-manager mapping
- scoped-domain-access mapping

Bootstrap and recovery must not depend on Authentik being healthy.

## Plugin runtime foundation

Plugin runtime requirements:

- protobuf contract layout
- gRPC client/server skeleton
- plugin registry
- generated or admitted service credentials
- authenticated health/version/capability RPCs
- unauthenticated plugin gRPC rejected
- request/correlation IDs
- deadlines
- structured errors
- no in-process loading
- no Docker socket
- no broad filesystem mounts
- plugin failure cannot corrupt core state

v0 defines seams only; it does not build a plugin ecosystem.

## TLS model

v0 models TLS modes:

- manual certificate
- Let's Encrypt
- dev/internal self-signed only when explicitly non-production

Validation checks:

- hostname consistency
- certificate path presence/shape
- public URL consistency
- Authentik/OIDC redirect URL consistency
- no production silent fallback to self-signed certificates

## GOTTH admin shell

v0 UI includes only the shell:

- layout/navigation
- login/session shell
- dashboard/status page
- read-only config/status views
- Authentik/bootstrap status page

All mutations route through service/auth/audit layers.

## Verification gates

- container build succeeds
- migrations run on empty DB
- typed config validates and renders deterministic output
- diff/apply writes audit event
- audit writer records redacted mutation events
- permission simulator explains allow/deny
- Authentik profile exists in topology
- plugin health/version/capability gRPC contracts compile
- authenticated plugin health/version/capability calls succeed with admitted service credentials
- unauthenticated plugin gRPC calls are rejected
- plugin failure isolation is covered by tests or contract checks
- `git diff --check` and Go tests pass
