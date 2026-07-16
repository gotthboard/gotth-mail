# Global Coverage Map

This file is the project-level coverage artifact referenced by `workflow.toml`.

## Coverage posture

v0 foundation implementation now exists. New features still start with missing executable coverage. A feature cannot move to done until it records relevant tests for the behavior it touches or records an explicit accepted gap with reason, risk, owner, and next coverage increment.

## Subsystems and required harnesses

| Subsystem | Required harnesses | Initial state | High-risk gaps |
| --- | --- | --- | --- |
| Config/render/apply | unit, golden render, audit integration | v0 config/render/apply tests, CLI staged/apply smoke in `cmd/gmf`, and v1 daemon config render/source-header tests in `internal/render` | future DNS/TLS/plugin-specific renderers still pending |
| Store/migrations | migration, constraint, upgrade/downgrade where safe | v0 migration/schema helper tests plus embedded Postgres SQL execution tests in `internal/store`, including enum/check constraints and SQL audit persistence | downgrade path deferred beyond v0 |
| Audit/authz | unit, negative, fail-closed integration | v0 audit redaction, SQL audit source persistence, and authz explain tests in `internal/audit`, `internal/store`, and `internal/authz` | richer integration coverage required as mutations expand |
| Plugin runtime | protobuf contract, authenticated/unauthenticated gRPC, failure isolation | v0 generated protobuf bindings, metadata/deadline/status-code plugin control tests, and bufconn gRPC transport tests in `internal/plugin` and `test/contract` | future plugin implementations still missing |
| Daemon contracts | Postfix/Dovecot/Rspamd contract and negative tests | initial v1 HTTP/JSON decision contract tests in `internal/daemon` plus API route wiring tests in `internal/api` | daemon-native adapter integration and full reference Compose mail-flow smoke still pending |
| DNS/TLS/ACME | unit, doctor, reference integration | initial v0 TLS config validation tests in `internal/config` | ACME implementation and doctor checks deferred |
| Diagnostics/smoke | CLI/API, machine-readable output, reference Compose smoke | v0 CLI staged render/apply smoke, API shell route tests, contract checks, and Docker build smoke evidence | reference Compose runtime smoke still deferred |
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
