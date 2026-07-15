# Global Coverage Map

This file is the project-level coverage artifact referenced by `workflow.toml`.

## Coverage posture

v0 foundation implementation now exists. New features still start with missing executable coverage. A feature cannot move to done until it records relevant tests for the behavior it touches or records an explicit accepted gap with reason, risk, owner, and next coverage increment.

## Subsystems and required harnesses

| Subsystem | Required harnesses | Initial state | High-risk gaps |
| --- | --- | --- | --- |
| Config/render/apply | unit, golden render, audit integration | initial v0 tests in `internal/config`, `internal/render`, `internal/apply` | future daemon-specific renderers still missing |
| Store/migrations | migration, constraint, upgrade/downgrade where safe | initial v0 migration/schema helper tests plus SQLite-backed SQL execution tests in `internal/store` | downgrade path deferred beyond v0 |
| Audit/authz | unit, negative, fail-closed integration | initial v0 audit redaction and authz explain tests in `internal/audit` and `internal/authz` | richer integration coverage required as mutations expand |
| Plugin runtime | protobuf contract, authenticated/unauthenticated gRPC, failure isolation | initial v0 proto contract, plugin control tests, and bufconn gRPC transport tests in `internal/plugin` and `test/contract` | generated protobuf bindings remain future work |
| Daemon contracts | Postfix/Dovecot/Rspamd contract and negative tests | missing | fake success, Authentik-dependent mail path |
| DNS/TLS/ACME | unit, doctor, reference integration | initial v0 TLS config validation tests in `internal/config` | ACME implementation and doctor checks deferred |
| Diagnostics/smoke | CLI/API, machine-readable output, reference Compose smoke | initial v0 CLI/API smoke, contract checks, and Docker build smoke evidence | reference Compose runtime smoke still deferred |
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
