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
| Plugin runtime | protobuf contract, authenticated/unauthenticated gRPC, failure isolation | v0 generated protobuf bindings, metadata/deadline/status-code plugin control tests, v1 first-plugin capability/auth tests in `internal/plugin`, and reference Compose plugin container checks in `test/contract` | seam-specific plugin APIs and live plugin integration still pending |
| Daemon contracts | Postfix/Dovecot/Rspamd contract and negative tests | initial v1 HTTP/JSON decision contract tests in `internal/daemon`, API route wiring tests in `internal/api`, and real reference Compose Postfix policy-socket, Dovecot generated auth/userdb, and Rspamd milter DKIM smoke in `scripts/reference-runtime-smoke.sh` | production daemon adapter hardening and broader edge-case matrix still pending; v1 root now includes CLI doctor and mail admin CRUD/UI smoke-level coverage |
| DNS/TLS/ACME | unit, doctor, reference integration | v0 TLS config validation plus v1 exact DNS readiness, certificate SAN/expiry, MTA-STS/TLS-RPT, and loud ACME failure tests in `internal/diag` | live ACME issuance and full doctor/reference integration still pending |
| Diagnostics/smoke | CLI/API, machine-readable output, reference Compose smoke | v0 CLI/API smoke, v1 doctor/debug/trace/queue/smoke-result/snapshot tests in `internal/ops`, API route tests in `internal/api`, and real reference Compose SMTP policy reject/accept, IMAP, DKIM-signed delivery, and Roundcube IMAP-backed webmail smoke in `scripts/reference-runtime-smoke.sh` | broader hostile-content/webmail security smoke remains future v4 scope; deterministic SMTP client smoke and live doctor ACME/manual-cert loud-failure proof are covered |
| OIDC/Auth/SCIM | token validation, replay, SCIM success/failure, Authentik-compatible integration | v2 OIDC discovery/state/nonce/redirect/JWKS signature/claim/session tests in `internal/authn`; SQL-backed OIDC state/session tests in `internal/authn`; authorization-code exchange seam and hardened session-cookie callback tests in `internal/authn`/`internal/api`; SCIM bearer-auth provisioning, SQL-backed mailbox/token persistence, restart reload, and fail-closed audit mutation tests in `internal/api`/`internal/identity` | installed Authentik provider discovery/JWKS/authorize redirect smoke now covered by `scripts/live-authentik-oidc-smoke.sh`; OIDC discovery/JWKS fetcher covered by `internal/authn` httptest provider; runtime Authentik env discovery wiring covered by `cmd/gophermailforge` tests and live local runtime redirect smoke against installed Authentik; SQL-backed OIDC state/session store covered by embedded Postgres tests; browser-shaped GMF redirect login/GET callback/session-cookie route covered by signed-token API regression; live browser/passkey code redemption and group-claim assertion still pending |
| App passwords | verifier-only storage, Dovecot auth, secret-once behavior | v2 app-password create/list/revoke, secret-once/no-verifier disclosure, SQL-backed token/verifier persistence with restart/revocation proof, Dovecot verifier path, scoped API-token authorization, and audit-fail-closed mutation tests in `internal/identity`, `internal/api`, and `internal/daemon` | live client compatibility matrix still pending; durable app-password persistence is covered by embedded Postgres restart tests; app-password list auth hole repaired |
| Backup/import/rollback | isolated restore, import preview/apply binding, no silent weakening | v3 authenticated operator API tests, no forged snapshot lookup/diff tests, Mailu preview/apply hash/fingerprint/actor validation, stricter candidate/verifier validation, and audit-durable bulk apply tests in `internal/api`/`internal/ops` | backup verification remains modeled; live isolated restore and live Mailu import compatibility still pending; UI/API auth bypasses repaired and fake UI backup success removed |
| Admin UI | HTMX/API service path integration, no bypass | v3 UI route tests plus API-backed operator workflow tests cover the repaired authenticated service paths | broader browser-level HTMX integration remains pending |
| Webmail | IMAP/SMTP integration, MIME/XSS/CSP, attachment safety | v4 webmail client/sender unit tests and authenticated mailbox-scoped API wiring tests cover folder/list/search/read, draft submit, request-body From rejection/binding, resolver-before-signer exact-sender seam, MIME header injection rejection, non-colliding draft IDs, bounded search, escaped hostile HTML, CSP, and attachment safety | production IMAP/SMTP adapters, cryptographic OpenPGP integration, rich HTML parser/allowlist sanitizer, and persistent mailbox-owned draft storage remain pending; draft submit ownership hole repaired |
| Notifications | plugin gRPC, Telegram redaction, actor mapping, approval binding | missing | chat as authority, replayed approval |

## Accepted exceptions

None.

## Smallest next coverage increment

For v1 admission, run a fresh cold root review over the reference runtime smoke commit, then move to v2 only after v1 is admitted or explicitly split with an approved exception.


## v2-v4 admission repair coverage note — 2026-07-18

A cold admission review rejected the prior v2/v3/v4 evidence as overclaimed. The repair pass added layered vertical slices rather than broad cosmetic cleanup:

- v2: OIDC authorization-code exchange seam, secure session-cookie API callback, audit-fail-closed identity mutations, and scoped app-password token authority. Evidence: `workflow/features/v2.identity-provisioning/evidence/2026-07-18-admission-repair.md`.
- v3: authenticated/authorized operator API routes, no forged snapshot status, redacted audit read boundary, stricter Mailu candidate validation, non-empty bulk scope, and audit-durable bulk apply. Evidence: `workflow/features/v3.ops-import-admin/evidence/2026-07-18-admission-repair.md`.
- v4: authenticated mailbox-scoped webmail API wiring, exact-sender resolver-before-signer seam, safer MIME construction, bounded search, random draft IDs, and conservative hostile HTML text rendering. Evidence: `workflow/features/v4.webmail/evidence/2026-07-18-admission-repair.md`.

These repairs do not claim live Authentik/Mailu/IMAP/SMTP/OpenPGP production integration. Those remain explicit gaps above.

## v1 root completion coverage note — 2026-07-16

The v1 completion pass added coverage for `gmf doctor --format text|json`, domain/user/alias admin CRUD backing behavior, server-rendered admin screens, seam-specific first-plugin contracts, deterministic SMTP smoke, and live reference doctor output for loud ACME/manual-certificate failure. Remaining hostile-content webmail security and production public-domain ACME issuance are explicitly later-version/deployment-scope work, not hidden v1 gaps.

| OpenPGP outbound signing | Exact-user OpenPGP/MIME signatures for every outbound email, key state failures, audit fingerprints | planned v5 feature `v5.notifications.openpgp-signed-email`; docs/spec requirement recorded | implementation pending; unsigned fallback must remain blocked |

## Full-finish correction note — 2026-07-18

Danny rejected the prior "enough for gate" posture. v2, v3, and v4 roots have been reopened in `workflow.toml` and explicit production finishing children were added. This correction also repaired immediate trust-boundary holes:

- app-password list now requires scoped authorization; cross-mailbox listing is denied.
- legacy audit event list now requires ops-admin authorization and redacts responses.
- webmail draft submit verifies draft ownership against the authenticated mailbox scope.
- UI mutation routes require bearer authorization instead of fabricating `local_admin ui`; backup verification UI no longer manufactures a fake verified artifact.
- durable schema contracts now include OIDC login states, sessions, backup verification records, snapshots, and mailbox-owned webmail drafts.

Remaining production integrations are not done and must not be represented as done: live Authentik, live Mailu, isolated backup restore, production IMAP/SMTP, OpenPGP crypto/canonicalization, raw MIME parsing, rich HTML sanitizer/browser proof, and durable runtime wiring.
