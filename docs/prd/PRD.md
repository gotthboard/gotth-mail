# GOTTH Mail PRD

## Product summary

GOTTH Mail is a Docker/Compose-deployed Go mail-server control plane and deployment system using Mailu as the reference architecture and executable behavioral specification. It keeps the proven mail-daemon split while replacing the control plane with typed configuration, explicit contracts, strict validation, observable operations, and containerized plugin boundaries.

GOTTH Mail is not a Mailu fork and must not mechanically copy Mailu's Python/Flask/SQLAlchemy behavior.

## Required stack

- Control plane: Go, shipped as a Docker container.
- Admin UI: GOTTH stack — Go + templ + Tailwind + HTMX.
- Mail daemons: Postfix, Dovecot, Rspamd, nginx-style front service.
- Identity: required Authentik service/profile, never embedded.
- Provisioning: OIDC for web SSO; SCIM for identity provisioning.
- Webmail: required supported external webmail service until custom webmail is deliberately built later.
- Plugins: separate Docker containers communicating with the control plane over gRPC/protobuf.
- Persistence: explicit relational schema and migrations.
- Config: typed, validated, generated, diffed, applied explicitly, and audited.

## Reference drafts

GOTTH Mail exact-sender OpenPGP/MIME requirements are traced to these local reference drafts:

- [Exact Sender Identity Binding for OpenPGP/MIME Signed Email](../reference/openpgp-exact-sender/draft-hunn-openpgp-exact-sender-signatures-01.md)
- [Operational Identity History and Audit Indexing for Exact Sender Binding](../reference/openpgp-exact-sender/draft-hunn-exact-sender-operational-identity-history-00.md)

These drafts are project reference material. Version PRDs, architecture documents, implementation specs, tests, and workflow evidence still decide which parts are implemented in each version.

## Hard invariants

1. Do not break mail delivery because Authentik is down.
2. Do not embed Authentik or plugins into the control-plane binary.
3. Do not make the daemon contracts pluggable early.
4. Do not let plugins own policy.
5. Do not let UI/API/CLI/Telegram bypass validation, authorization, confirmation, mutation rules, or audit.
6. Do not silently log secrets.
7. Do not silently fall back to self-signed certs in production.
8. Do not claim rollback unless the required verified backup/snapshot exists.
9. Do not invent a mail-only password hash when Authentik-compatible Django encoded hashes are required.
10. Do not build custom webmail before the control plane is solid.

## Reference: Mailu concepts to preserve

Preserve where valuable:

- service decomposition
- Docker/Compose deployment model
- domain/user/alias/relay/fetch/token concepts
- daemon-facing lookup endpoints
- DNS guidance semantics
- DKIM lifecycle expectations
- Mandatory exact-user OpenPGP signing for every outbound email; unsigned outbound mail is not allowed.
- REST API coverage in spirit
- SCIM user provisioning shape
- admin/delegation concepts

Reject:

- permissive scalar coercion
- fake success/no-op API behavior
- untyped environment sprawl as the core model
- UI-only behavior with no API/service equivalent
- implicit ORM behavior as a contract
- plugin abstractions around the mail-server spine before the spine works

## Version PRDs

The detailed capability-workstream plans live in separate files. Their
historical `v0` through `v5` identifiers are workflow IDs, not published
product versions:

- [v0 Foundation](PRD-v0-foundation.md)
- [v1 Mail Core](PRD-v1-mail-core.md)
- [v2 Identity + Provisioning](PRD-v2-identity-provisioning.md)
- [v3 Ops + Import + Mature Admin](PRD-v3-ops-import-admin.md)
- [v4 Custom Webmail](PRD-v4-webmail.md)
- [v5 Notifications](PRD-v5-notifications.md)
- [1.0 release line](PRD-release-1.0.md)

## Capability workstreams for 1.0

### Foundation (`v0.foundation` historical ID)

Build the containerized control-plane base: Go project, GOTTH shell, typed config, migrations, audit capture, permission core, Authentik base, app-password/token primitives, TLS config validation, plugin runtime foundation, and plugin seam definitions.

### Mail Core (`v1.mail-core` historical ID)

Build the actual mail-server control path: Postfix/Dovecot/Rspamd contracts, DNS/TLS/Let’s Encrypt, MTA-STS/TLS-RPT, doctor, lookup debugger, mail flow trace, queue visibility, smoke tests, snapshots, and first plugin containers for webmail/DNS/cert/backup.

### Identity + Provisioning (`v2.identity-provisioning` historical ID)

Build identity and provisioning on top of the working mail core: OIDC login, strict token validation, Authentik role mapping, SCIM, app passwords/mail-client tokens, permission simulator full coverage, and identity UI.

### Ops + Import + Mature Admin (`v3.ops-import-admin` historical ID)

Build operational maturity: audit UI, backup/restore verification, snapshot/rollback UI, Mailu import source plugin, abuse/rate-limit dashboard, mature admin UI, config diff viewer, and rollback guidance.

### Custom Webmail (`v4.webmail` historical ID)

Only after the control plane is solid and the v4 cutline is explicitly accepted, build custom GOTTH webmail: IMAP core, MIME-safe message rendering, compose/send, attachments, drafts, search, identities/signatures, sieve/rules, mobile UI, and XSS hardening.

### Notifications (`v5.notifications` historical ID)

Build the notification backend plugin seam, with Telegram as the first required implementation: operational alerts, read-only commands, later approval workflows, actor mapping, and audit coverage.

These workstreams all belong to the `1.0.0` release line. Incomplete integrated
builds are `1.0.0-alpha.N`; feature-complete acceptance builds are
`1.0.0-beta.N`; only the complete admitted stack becomes stable `1.0.0`.

## Plugin boundaries

Pluggability is allowed only at narrow mechanism seams:

1. Webmail provider
2. DNS provider integration
3. ACME/certificate backend
4. Backup storage backend
5. Notification backend
6. Import source

Not pluggable early:

- Postfix/Dovecot/Rspamd contracts
- audit logging
- permission model
- Authentik role mapping
- config rendering core
- database/migration layer
- daemon lookup debugger

Core owns policy. Plugins provide mechanisms.

Plugins must be Docker containers, communicate over gRPC/protobuf, authenticate with service identity credentials, expose health/version/capability RPCs, use deadlines and structured errors, and must not receive broad filesystem mounts or Docker socket access.

## Architecture gate

Architecture work may begin only after the PRD set is clean and followed by:

- Mailu reference inventory
- internal daemon API contract document
- data model document
- generated config responsibility map
- deployment topology document
- explicit MVP cutline

Do not jump straight into coding. That is how control planes become piles of accidental behavior.

## Global outbound email signing invariant

Every outbound email produced or relayed by GOTTH Mail must follow [Exact Sender Identity Binding for OpenPGP/MIME Signed Email](../reference/openpgp-exact-sender/draft-hunn-openpgp-exact-sender-signatures-01.md) for the asserted sender/user identity. DKIM remains required for domain/server authenticity, but it is not enough: OpenPGP is the exact-user-origin proof.

The verifier must be able to answer **exactly which configured user identity signed this message**. A valid domain signature, relay signature, shared mailbox signature, or unmapped OpenPGP key is not sufficient. The signing key must be bound to the asserted `From`/`Sender` identity and current user/key state.

Rules:

- no unsigned outbound email;
- no silent fallback to unsigned mail;
- signing failure blocks send and produces actionable doctor/audit status;
- signatures bind the canonical MIME body and relevant headers according to the selected OpenPGP/MIME profile;
- key ownership, rotation, revocation, expiry, and disabled-user behavior must be explicit and auditable;
- imported messages may remain historically unsigned, but any newly sent, resent, automated, notification, approval, or system-generated outbound message must be signed before leaving the system.


The companion operational profile, [Operational Identity History and Audit Indexing for Exact Sender Binding](../reference/openpgp-exact-sender/draft-hunn-exact-sender-operational-identity-history-00.md), governs project requirements for temporal identity state, address/name history, search/audit indexing, downgrade detection, key-rotation continuity, and forensic export where those capabilities are implemented.

The signature requirement is not merely provenance for a domain or server. Verification must answer exactly which configured user identity signed the message. If the signer cannot be mapped to the asserted From/Sender identity and active user/key binding, the message is treated as unsigned/invalid.
