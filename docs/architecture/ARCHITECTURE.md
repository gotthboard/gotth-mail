# GOTTH Mail Architecture

## Purpose

This document defines the system-wide architecture for GOTTH Mail. Version-specific architecture details live in this directory and must remain traceable to the matching PRD files.

GOTTH Mail is a Docker/Compose-deployed Go control plane for a self-hosted mail stack. It uses Mailu as the reference architecture, but replaces Mailu's Python control plane with explicit Go services, typed configuration, containerized plugin mechanisms, audited mutations, and daemon-facing contracts that are testable without guessing.

## Architecture documents

- [v0 Foundation](v0-foundation.md) — from [PRD-v0-foundation.md](../prd/PRD-v0-foundation.md)
- [v1 Mail Core](v1-mail-core.md) — from [PRD-v1-mail-core.md](../prd/PRD-v1-mail-core.md)
- [v2 Identity + Provisioning](v2-identity-provisioning.md) — from [PRD-v2-identity-provisioning.md](../prd/PRD-v2-identity-provisioning.md)
- [v3 Ops + Import + Mature Admin](v3-ops-import-admin.md) — from [PRD-v3-ops-import-admin.md](../prd/PRD-v3-ops-import-admin.md)
- [v4 Custom Webmail](v4-webmail.md) — from [PRD-v4-webmail.md](../prd/PRD-v4-webmail.md)
- [v5 Notifications](v5-notifications.md) — from [PRD-v5-notifications.md](../prd/PRD-v5-notifications.md)
- [1.0 release line](release-1.0.md) — from [PRD-release-1.0.md](../prd/PRD-release-1.0.md)
- [2.0 Go-native mail engine](release-2.0.md) — from [PRD-release-2.0.md](../prd/PRD-release-2.0.md)

The `v0` through `v5` labels above are retained capability-workstream IDs, not
published major versions. The product release state machine is defined by the
1.0 release-line architecture. Product 2.0 is a separate future release line
that replaces the external mail daemons with GOTTH Mail-owned Go roles.

## Exact sender architecture references

Outbound email signing architecture is constrained by:

- [Exact Sender Identity Binding for OpenPGP/MIME Signed Email](../reference/openpgp-exact-sender/draft-hunn-openpgp-exact-sender-signatures-01.md)
- [Operational Identity History and Audit Indexing for Exact Sender Binding](../reference/openpgp-exact-sender/draft-hunn-exact-sender-operational-identity-history-00.md)

The core profile controls signing, exact identity binding, delegation, and fail-closed behavior. The operational profile controls temporal identity state, address/name history, search/audit indexing, downgrade detection, key-rotation continuity, and forensic export where implemented.

## Core components

### Control plane container

The GOTTH Mail control plane is a Go service shipped as a Docker container. It owns:

- typed configuration parsing and validation
- database migrations
- domain/user/alias/relay/token state
- generated daemon config rendering
- render/diff/apply gates
- audit logging
- permission decisions
- daemon-facing internal APIs
- public admin API
- GOTTH admin UI
- plugin registry and gRPC client runtime

### Mail daemon containers

The mail path remains built on proven daemons:

- front/proxy service for HTTP(S), SMTP ingress, and ACME challenge routing
- Postfix for SMTP delivery/submission decisions
- Dovecot for IMAP/auth/userdb/quota behavior
- Rspamd for local-domain/DKIM/spam-related decisions
- selected external webmail provider until v4 custom webmail is accepted

GOTTH Mail does not reimplement SMTP, IMAP, spam filtering, DKIM signing, or webmail in early versions.

### Identity service

Authentik is a required adjacent service/profile for identity flows. It is not embedded. GOTTH Mail integrates with it through:

- OIDC for web/session login
- SCIM for provisioning
- mandatory group/role mappings for global admins, domain managers, and scoped domain access

Authentik outage may break new SSO/provisioning actions, but must not break mail delivery or daemon lookup paths.

### Plugin containers

Plugins are mechanism providers. They run as separate Docker containers and communicate with the control plane over gRPC/protobuf on the internal deployment network.

Allowed plugin seams:

1. webmail provider
2. DNS provider integration
3. ACME/certificate backend
4. backup storage backend
5. notification backend
6. import source

Not pluggable early:

- Postfix/Dovecot/Rspamd contracts
- audit logging
- permission model
- Authentik role mapping
- config rendering core
- database/migration layer
- daemon lookup debugger

Core owns policy. Plugins provide mechanisms.

## Trust boundaries

### External operator surfaces

- GOTTH admin UI
- versioned REST API
- CLI
- future Telegram/notification approval prompts

All mutation paths must use the same authorization, validation, confirmation, mutation, and audit services.

### Internal daemon APIs

Postfix, Dovecot, Rspamd, fetch/autoconfig, and related internal callers use explicit internal contracts. These contracts are product-critical and not plugin seams.

### Plugin gRPC boundary

Plugin calls require:

- service identity authentication
- explicit protobuf contracts
- health/version/capability RPCs
- deadlines
- structured errors
- request/correlation IDs
- no Docker socket access
- no broad filesystem mounts

Plugin failures degrade the mechanism they implement without corrupting core state.

## State ownership

The control plane owns canonical state:

- domains
- users/mailboxes
- aliases
- relays
- tokens/app passwords
- Authentik identity references
- role/scoped-access mappings
- audit events
- generated-config metadata
- migration history
- snapshots/backup verification metadata

Plugins may parse, store, send, issue, or verify mechanisms, but they do not admit state into the core database without core validation.

## Configuration flow

1. Operator supplies typed config.
2. Control plane validates config.
3. Control plane renders generated config into a controlled output area.
4. Operator reviews diff.
5. Explicit apply gate commits generated output.
6. Apply event is audited.
7. Doctor/smoke tests verify runtime behavior.

Generated files must be reproducible from database state + typed config + selected deployment policy.

## Audit and permissions

Audit capture starts in v0. Audit UI/search/export arrives later.

Audit records include actor, action, resource, redacted before/after summary, result, request/correlation ID, and failure code when applicable.

Permission checks use an actor/action/resource model. The permission simulator explains why an action is allowed or denied. UI/API/CLI/Telegram must not bypass the same decision path.

## Deployment topology

The first supported deployment target is Docker/Compose. Kubernetes or arbitrary daemon topologies are not early architecture goals.

Reference topology includes:

- `gotth-mail` control-plane container
- database container or configured external DB
- front/proxy container
- Postfix container
- Dovecot container
- Rspamd container
- required Authentik profile/services
- selected webmail provider
- plugin containers on internal network

## Architecture gates

No implementation should start until the matching version PRD and architecture doc define:

- state ownership
- trust boundaries
- API/contract shape
- failure behavior
- audit behavior
- test/verification gates

If a version cannot be tested independently, the version is not properly cut.
