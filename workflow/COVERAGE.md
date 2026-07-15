# Global Coverage Map

This file is the project-level coverage artifact referenced by `workflow.toml`.

## Coverage posture

No implementation code exists yet. Every feature starts with missing executable coverage. A feature cannot move to done until it records relevant tests for the behavior it touches or records an explicit accepted gap with reason, risk, owner, and next coverage increment.

## Subsystems and required harnesses

| Subsystem | Required harnesses | Initial state | High-risk gaps |
| --- | --- | --- | --- |
| Config/render/apply | unit, golden render, audit integration | missing | generated config drift, unaudited apply |
| Store/migrations | migration, constraint, upgrade/downgrade where safe | missing | weak DB constraints, token plaintext |
| Audit/authz | unit, negative, fail-closed integration | missing | unaudited mutation, bypassed authz |
| Plugin runtime | protobuf contract, authenticated/unauthenticated gRPC, failure isolation | missing | uncredentialed plugin, state corruption on failure |
| Daemon contracts | Postfix/Dovecot/Rspamd contract and negative tests | missing | fake success, Authentik-dependent mail path |
| DNS/TLS/ACME | unit, doctor, reference integration | missing | silent self-signed fallback, bad remediation |
| Diagnostics/smoke | CLI/API, machine-readable output, reference Compose smoke | missing | green local tests with broken deployment |
| OIDC/Auth/SCIM | token validation, replay, SCIM success/failure, Authentik-compatible integration | missing | unsigned-claim trust, provisioning bypass |
| App passwords | verifier-only storage, Dovecot auth, secret-once behavior | missing | plaintext/replay/exposure |
| Backup/import/rollback | isolated restore, import preview/apply binding, no silent weakening | missing | fake rollback, credential weakening |
| Admin UI | HTMX/API service path integration, no bypass | missing | UI-only mutation path |
| Webmail | IMAP/SMTP integration, MIME/XSS/CSP, attachment safety | missing | hostile HTML execution, direct mailbox access |
| Notifications | plugin gRPC, Telegram redaction, actor mapping, approval binding | missing | chat as authority, replayed approval |

## Accepted exceptions

None.

## Smallest next coverage increment

For v0, start with config parser validation tests, migration-on-empty-DB tests, audit redaction tests, authz explain tests, and plugin health/version/capability authenticated/unauthenticated contract tests.
