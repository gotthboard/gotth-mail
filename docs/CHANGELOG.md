# Changelog

All meaningful repository changes must be recorded here in the same commit that makes the change.

This changelog is operator-facing project history, not a replacement for workflow evidence. Entries must be verbose enough that a reviewer can understand what changed without reading the full diff first.

## Rules

- Update this file for every change that modifies product docs, architecture, implementation specs, workflow state, source code, tests, deployment behavior, security posture, or user-visible behavior.
- Use the newest entry at the top of the `Unreleased` section until a release/version tag exists.
- Every entry must include:
  - date and time, including timezone
  - commit identifier
  - affected files
  - verbose explanation of what changed and why
  - verification performed
- Historical entries must use the real commit hash.
- The entry for the commit currently being created cannot contain its final Git hash because Git hashes the changelog content itself. Use `current commit; hash assigned by Git after commit` for that one case, then use real hashes for historical entries.
- Do not record private secrets, credentials, raw tokens, or unredacted before/after values.
- Do not use the changelog as a fake done signal; workflow evidence and verification still live under `workflow/`.

## Unreleased

### 2026-07-16 13:15 CDT — Draft v4 custom webmail protocol seams (not admitted)

Commit: current commit; hash assigned by Git after commit

Affected files:

- `internal/webmail/webmail.go`
- `internal/webmail/webmail_test.go`
- `docs/CHANGELOG.md`
- `workflow.toml`
- `workflow.events.jsonl`
- `workflow/features/v4.webmail/README.md`
- `workflow/features/v4.webmail/provider-imap-compose/README.md`
- `workflow/features/v4.webmail/provider-imap-compose/evidence/2026-07-16-provider-imap-compose.md`
- `workflow/features/v4.webmail/search-security-ux/README.md`
- `workflow/features/v4.webmail/search-security-ux/evidence/2026-07-16-search-security-ux.md`
- `workflow/features/v4.webmail/evidence/2026-07-16-v4-root-completion.md`

Explanation:

Drafted the v4 custom webmail protocol seam implementation: external-provider continuity, folder list, message list/read, pagination/windowing, quota display, current-folder search, draft save, submit, send failure reporting, and mandatory OpenPGP/MIME signing structure validation for outbound sends. The webmail sender rejects unsigned or mismatched signing identity attempts and records audit metadata without treating OIDC as SMTP.

Added MIME/HTML safety foundations: script stripping, event-handler blocking, javascript URL blocking, remote image blocking, CSP baseline, attachment filename traversal sanitization, and oversized attachment fallback behavior. Webmail remains a provider/client model and does not replace Dovecot/SMTP or mutate control-plane state directly.

Verification:

- Confirmed `go test ./internal/webmail` passes for seam/model draft coverage.
- Confirmed `git diff --check -- .` passes.
- Confirmed `go test ./...` passes.

### 2026-07-16 12:55 CDT — Implement v3 ops, import, and mature admin workflows

Commit: efbfa3b

Affected files:

- `cmd/gmf/main.go`
- `cmd/gmf/main_test.go`
- `internal/api/api.go`
- `internal/api/api_test.go`
- `internal/api/v3.go`
- `internal/httpui/httpui.go`
- `internal/httpui/httpui_test.go`
- `internal/ops/v3.go`
- `internal/ops/v3_test.go`
- `docs/CHANGELOG.md`
- `workflow.toml`
- `workflow.events.jsonl`
- `workflow/features/v3.ops-import-admin/README.md`
- `workflow/features/v3.ops-import-admin/audit-backup-snapshots/README.md`
- `workflow/features/v3.ops-import-admin/audit-backup-snapshots/evidence/2026-07-16-audit-backup-snapshots.md`
- `workflow/features/v3.ops-import-admin/mailu-import/README.md`
- `workflow/features/v3.ops-import-admin/mailu-import/evidence/2026-07-16-mailu-import.md`
- `workflow/features/v3.ops-import-admin/abuse-bulk-ui/README.md`
- `workflow/features/v3.ops-import-admin/abuse-bulk-ui/evidence/2026-07-16-abuse-bulk-ui.md`
- `workflow/features/v3.ops-import-admin/evidence/2026-07-16-v3-root-completion.md`

Explanation:

Implemented v3 operator surfaces for audit filtering/export/retention, backup verification, snapshot rollback guidance, Mailu import preview/apply, abuse/rate-limit/deferred correlation, and mature bulk admin workflows. Preview/apply flows now keep server-side import and bulk preview/job state instead of trusting caller-supplied preview bodies. Backup verification reads a storage artifact, restores into an isolated modeled state, runs schema migration checks, and validates daemon contracts before marking a backup verified. Rollback guidance refuses fake safety without verified restore state.

Mailu import preview classifies unsupported/weakening inputs, rejects plaintext secrets and unsupported verifier algorithms, requires source fingerprint/hash/actor/expiry binding, exposes `GET /api/v1/imports/{id}`, and audits apply. Bulk workflows whitelist operations, store previews/jobs server-side, require confirmation/hash/actor/expiry checks, emit per-item audit events, and expose `GET /api/v1/bulk/jobs/{id}`. v3 UI sections include working backup verify, Mailu preview, and bulk preview forms rather than dead links.

Verification:

- Confirmed `go test ./cmd/gmf` passes.
- Confirmed `go test ./internal/ops` passes.
- Confirmed `go test ./internal/api` passes.
- Confirmed `go test ./internal/httpui` passes.
- Confirmed `git diff --check -- .` passes.
- Confirmed `go test ./...` passes.

### 2026-07-16 12:05 CDT — Finish v2 identity provisioning

Commit: fc2ce0e

Affected files:

- `internal/identity/identity.go`
- `internal/identity/identity_test.go`
- `internal/api/api.go`
- `internal/api/api_test.go`
- `internal/api/scim.go`
- `internal/daemon/daemon.go`
- `internal/daemon/daemon_test.go`
- `internal/httpui/httpui.go`
- `internal/httpui/httpui_test.go`
- `docs/CHANGELOG.md`
- `workflow.toml`
- `workflow.events.jsonl`
- `workflow/features/v2.identity-provisioning/README.md`
- `workflow/features/v2.identity-provisioning/oidc-sessions/README.md`
- `workflow/features/v2.identity-provisioning/scim/README.md`
- `workflow/features/v2.identity-provisioning/scim/evidence/2026-07-16-scim.md`
- `workflow/features/v2.identity-provisioning/app-passwords-ui/README.md`
- `workflow/features/v2.identity-provisioning/app-passwords-ui/evidence/2026-07-16-app-passwords-ui.md`
- `workflow/features/v2.identity-provisioning/evidence/2026-07-16-v2-root-completion.md`

Explanation:

Completed the v2 identity/provisioning root. This change adds the remaining SCIM provisioning API, identity service, app-password/mail-client token behavior, Dovecot verifier integration, and identity UI surfaces. SCIM now exposes service metadata and Users list/create/read/replace/patch/disable behavior, requires verifier-backed bearer-token authentication for user routes, returns explicit unsupported Groups responses, validates payload/domain/password/patch failures, writes Django PBKDF2-SHA256 verifier strings for supplied mailbox passwords, synchronizes provisioned users into the daemon mailbox/passdb view, and emits audit events for provisioning mutations and denied/failure paths.

App passwords now support create/list/revoke through API routes. Create returns the plaintext generated secret once. Stored records retain verifier hashes only, app-password API routes require verifier-backed bearer-token authentication, list responses do not disclose plaintext secrets or verifier strings, revocation prevents future daemon `DovecotPassdb` verification, and mailbox/app-password verification uses the same Django-compatible verifier contract.

The identity UI now exposes OIDC/Auth, Authentik role mapping, SCIM status/test, app-password list/create/revoke, and permission simulator screens; SCIM test provisioning, app-password, and simulator UI flows use service authorization/audit paths. Workflow state marks all v2 children and the v2 root done, then advances the active feature to the first v3 child.

Verification:

- Confirmed `go test ./internal/identity` passes.
- Confirmed `go test ./internal/api` passes.
- Confirmed `go test ./internal/httpui` passes.
- Confirmed `git diff --check -- .` passes.
- Confirmed `go test ./...` passes.

### 2026-07-16 11:52 CDT — Add Authentik role mapping and permission simulator coverage

Commit: 33eedc5

Affected files:

- `internal/authz/authz.go`
- `internal/authz/authz_test.go`
- `internal/api/api.go`
- `internal/api/api_test.go`
- `internal/ops/ops.go`
- `internal/ops/ops_test.go`
- `docs/CHANGELOG.md`
- `workflow.toml`
- `workflow.events.jsonl`
- `workflow/features/v2.identity-provisioning/authentik-roles-authz/README.md`
- `workflow/features/v2.identity-provisioning/authentik-roles-authz/evidence/2026-07-16-authentik-roles-authz.md`

Explanation:

Implemented the Authentik role-mapping child for v2 identity provisioning. OIDC actors now carry Authentik groups and are evaluated against verified role mappings for global admin, domain manager, and scoped domain access. Authorization explanations now include matched rules for allowed decisions and missing requirements for denied decisions, so the permission simulator can explain the actual mechanism instead of returning a hardcoded local-admin answer.

The `/api/v1/authz/explain` route now decodes the submitted actor/action/resource request and evaluates it. Doctor now validates required role mappings and fails loudly when required mappings are missing, unverified, or reference unknown domains.

Verification:

- Confirmed `go test ./...` passes.
- Confirmed `git diff --check -- .` passes.

### 2026-07-16 11:05 CDT — Implement v2 OIDC sessions

Commit: b887c75

Affected files:

- `internal/authn/oidc.go`
- `internal/authn/oidc_test.go`
- `internal/api/api.go`
- `internal/api/api_test.go`
- `workflow.toml`
- `workflow.events.jsonl`
- `workflow/features/v2.identity-provisioning/oidc-sessions/evidence/2026-07-16-oidc-sessions.md`

Explanation:

Completed the first v2 child, `v2.identity-provisioning.oidc-sessions`. The implementation adds OIDC discovery validation, login state and nonce generation, authorization URL construction, exact redirect URI validation, browser-bound single-use callback state consumption, RS256 ID-token signature verification against JWKS, strict issuer/subject/audience/azp/exp/iat/nbf/nonce claim validation, session creation, and safe token-free error handling. API surfaces expose login start and callback validation without treating OIDC as IMAP/SMTP authentication.

The feature explicitly rejects unsigned `alg=none` tokens and has no unsigned-claim fallback. The next active v2 child is Authentik role mapping and permission simulator coverage.

Verification:

- Must pass `go test ./...`.
- Must pass `git diff --check -- .`.

### 2026-07-16 10:50 CDT — Start v2 identity provisioning

Commit: 43a56ca

Affected files:

- `workflow.toml`
- `workflow.events.jsonl`
- `workflow/features/v2.identity-provisioning/oidc-sessions/evidence/2026-07-16-start.md`

Explanation:

Started the v2 identity/provisioning root from the merged v1 admission baseline. The active child is `v2.identity-provisioning.oidc-sessions`, covering OIDC authorization-code login, single-use state, nonce/redirect validation, signed token validation through the configured issuer/JWKS, session behavior, no unsigned-claim fallback, and no token disclosure.

Verification:

- Must pass `git diff --check -- .`.
- Must pass `go test ./...`.

### 2026-07-16 10:22 CDT — Clarify exact-user OpenPGP identity binding

Commit: fcfdcdf

Affected files:

- `docs/prd/PRD.md`
- `docs/prd/PRD-v4-webmail.md`
- `docs/architecture/v4-webmail.md`
- `docs/implementation/v4-webmail.md`
- `docs/prd/PRD-v5-notifications.md`
- `docs/architecture/v5-notifications.md`
- `docs/implementation/v5-notifications.md`
- `workflow.toml`
- `workflow/COVERAGE.md`
- `workflow/features/v5.notifications/openpgp-signed-email/evidence/2026-07-16-openpgp-requirement.md`

Explanation:

Tightened the OpenPGP requirement so it cannot be misread as domain provenance. DKIM answers which domain/server handled a message; GopherMailForge requires exact-user-origin proof. Every outbound email signature must verify to exactly one configured active user or system notification identity, and that identity must be allowed to assert the message `From`/`Sender`. Ambiguous, unmapped, shared, revoked, expired, disabled, or mismatched signing keys fail closed and are treated as unsigned/invalid.

Verification:

- Must pass `git diff --check -- .`.
- Must pass `go test ./...`.

### 2026-07-16 10:21 CDT — Require OpenPGP signing for every outbound email

Commit: 6e3d5e1

Affected files:

- `docs/prd/PRD.md`
- `docs/prd/PRD-v4-webmail.md`
- `docs/architecture/v4-webmail.md`
- `docs/implementation/v4-webmail.md`
- `docs/prd/PRD-v5-notifications.md`
- `docs/architecture/v5-notifications.md`
- `docs/implementation/v5-notifications.md`
- `workflow.toml`
- `workflow/COVERAGE.md`
- `workflow.events.jsonl`
- `workflow/features/v5.notifications/openpgp-signed-email/README.md`
- `workflow/features/v5.notifications/openpgp-signed-email/evidence/2026-07-16-openpgp-requirement.md`

Explanation:

Made Danny's OpenPGP requirement canonical: every outbound email must be OpenPGP/MIME signed. DKIM remains required as domain/server proof, but it is not accepted as user-origin proof. Missing, revoked, expired, disabled, mismatched, or failed signing keys block send. The system must not silently fall back to unsigned email for convenience, notification delivery, resend, approval, or automated mail.

The requirement is recorded as a global product invariant, tied into v4 compose/send behavior, and added to v5 notification/email backend scope through a new planned feature `v5.notifications.openpgp-signed-email`. Verification requirements now include OpenPGP/MIME signed outbound email tests, no-unsigned-fallback tests, key-state rejection tests, identity mismatch tests, and audit fingerprint/signature-status tests.

Verification:

- Must pass `git diff --check -- .`.
- Must pass `go test ./...`.

### 2026-07-16 09:03 CDT — Finish v1 mail core root

Commit: a75b0f1

Affected files:

- `cmd/gmf/main.go`
- `cmd/gmf/main_test.go`
- `cmd/gophermailforge/main.go`
- `internal/admin/admin.go`
- `internal/admin/admin_test.go`
- `internal/api/api.go`
- `internal/httpui/httpui.go`
- `internal/httpui/httpui_test.go`
- `internal/plugin/seams.go`
- `internal/plugin/seams_test.go`
- `scripts/reference-runtime-smoke.sh`
- `test/contract/v1_plugins_contract_test.go`
- `workflow.toml`
- `workflow.events.jsonl`
- `workflow/COVERAGE.md`
- `workflow/features/v1.mail-core/evidence/2026-07-16-v1-root-completion.md`
- `workflow/features/v1.mail-core/review/2026-07-16-root-admission-review-final.md`
- v1 evidence/changelog files with historical commit-hash cleanup

Explanation:

Finished the v1 mail-core root after a cold admission review rejected the previous branch as overclaimed. The real Postfix/Dovecot/Rspamd/Roundcube reference smoke was already passing, but v1 still lacked root admission integrity and several declared v1 surfaces. This change adds the missing `gmf doctor --format text|json` CLI, a minimal server-rendered mail admin UI with domain/user/alias CRUD backing store, DNS/DKIM/doctor/lookup/plugin screens, seam-specific first-plugin service contracts for DNS export, certificate/manual ACME failure, backup verification, and Roundcube webmail config, and reference-runtime doctor proof that ACME/manual-cert behavior fails loudly instead of pretending success for `example.test`.

The reference smoke SMTP sections now use deterministic Python `smtplib` clients rather than timing-sensitive `printf | nc` scripting. Historical v1 changelog and evidence placeholders were replaced with real commit hashes. `workflow.toml` now marks `v1.mail-core` done and records root completion evidence/review.

Verification:

- Must pass `go test ./...`.
- Must pass `git diff --check -- .`.
- Must pass `scripts/reference-runtime-smoke.sh` against the reference Compose stack.

### 2026-07-16 02:11 CDT — Add v1 reference runtime smoke

Commit: 9f1aa30fb3920aa2ba4ccc30ed3cdf6088de3d5a

Affected files:

- `cmd/gophermailforge/main.go`
- `compose/reference/docker-compose.yml`
- `compose/reference/dovecot/dovecot.conf`
- `compose/reference/postfix/main.cf`
- `compose/reference/postfix/virtual_aliases`
- `compose/reference/postfix/virtual_mailboxes`
- `compose/reference/rspamd/local.d/dkim_signing.conf`
- `compose/reference/rspamd/local.d/worker-controller.inc`
- `compose/reference/rspamd/local.d/worker-normal.inc`
- `compose/reference/rspamd/local.d/worker-proxy.inc`
- `scripts/reference-runtime-smoke.sh`
- `test/contract/v1_plugins_contract_test.go`
- `workflow.toml`
- `workflow.events.jsonl`
- `workflow/COVERAGE.md`
- `workflow/features/v1.mail-core/reference-runtime-smoke/README.md`
- `workflow/features/v1.mail-core/reference-runtime-smoke/evidence/2026-07-16-reference-runtime-smoke.md`
- `workflow/features/v1.mail-core/review/2026-07-16-root-admission-review.md`

Explanation:

Added the narrow `v1.mail-core.reference-runtime-smoke` child required by root admission review. Reference Compose now runs real Postfix, Dovecot, Rspamd, and selected Roundcube external webmail provider service against a seeded GopherMailForge reference fixture instead of only modeling daemon contracts. The smoke harness starts the Compose stack, checks the internal daemon HTTP/JSON contracts, proves Postfix recipient policy uses the GopherMailForge policy socket by rejecting `nobody@example.test`, sends a real SMTP message to `alias@example.test`, proves alias delivery into the `smoke@example.test` Maildir, logs in over real Dovecot IMAP using generated GopherMailForge-derived auth/userdb material, fetches the delivered subject, logs into Roundcube over HTTP and verifies the delivered message appears through Roundcube’s IMAP-backed mail view, and proves Rspamd is in the Postfix milter path by requiring `DKIM-Signature` on the delivered message plus valid DKIM material/config.

This fixes the root blocker recorded by the previous v1 admission review, but it does not itself admit the root. A fresh cold root review should inspect this commit before opening a v1 admission PR.

Verification:

- Confirmed `go test ./...` passes.
- Confirmed `git diff --check -- .` passes.
- Confirmed `scripts/reference-runtime-smoke.sh` passes against the real reference Compose stack.

### 2026-07-16 01:56 CDT — Add v1 diagnostics, queue, smoke-result, and snapshot surfaces

Commit: f7f8162c93dac3f7ddc024c135936d553db09fbc

Affected files:

- `docs/CHANGELOG.md`
- `internal/api/api.go`
- `internal/api/api_test.go`
- `internal/ops/ops.go`
- `internal/ops/ops_test.go`
- `workflow.toml`
- `workflow.events.jsonl`
- `workflow/COVERAGE.md`
- `workflow/features/v1.mail-core/diagnostics-smoke-snapshots/evidence/2026-07-16-diagnostics-smoke-snapshots.md`

Explanation:

Completed the `v1.mail-core.diagnostics-smoke-snapshots` child by adding machine-readable doctor aggregation, lookup debugging, mail-flow trace modeling, queue visibility/mutations, smoke-result modeling, and snapshot capture. Queue flush/retry require explicit confirmations and emit audit events. Snapshots are explicitly marked as not rollback, avoiding fake safety. The API handler now exposes doctor, debug lookup, queue summary/deferred, and queue flush/retry routes.

This does not mark the v1 root complete. The implementation includes smoke-result modeling but has not yet proven a live reference Compose SMTP/IMAP/DKIM/webmail mail-flow smoke with real daemons. That root gap is recorded in workflow evidence and the global coverage map.

Verification:

- Confirmed `go test ./...` passes.
- Added tests for doctor status aggregation, lookup/debug trace shape, queue confirmation/audit behavior, snapshot-not-rollback semantics, and API route wiring.

### 2026-07-16 01:50 CDT — Add first v1 mechanism plugin containers

Commit: 6456a60cb0a5d86ea2ceb4bf83d9ae5e8fa6f8bf

Affected files:

- `Dockerfile`
- `cmd/gmf-plugin/main.go`
- `compose/reference/docker-compose.yml`
- `docs/CHANGELOG.md`
- `internal/plugin/first.go`
- `internal/plugin/first_test.go`
- `test/contract/v1_plugins_contract_test.go`
- `workflow.toml`
- `workflow.events.jsonl`
- `workflow/COVERAGE.md`
- `workflow/features/v1.mail-core/first-plugins/evidence/2026-07-16-first-plugins.md`

Explanation:

Completed `v1.mail-core.first-plugins` by adding the first mechanism plugin identities and reference container wiring for the selected external webmail provider, manual DNS export, manual/Let’s Encrypt certificate handling, and local filesystem backup storage. The new `gmf-plugin` runner exposes the existing v0 generated protobuf/gRPC `PluginControl` service, so first plugins authenticate with service identity metadata, require deadlines, and report capabilities through the same control contract as the rest of the plugin runtime.

The reference Compose file now includes all four plugin services and still avoids Docker socket mounts. The backup plugin receives only a named `/backup` volume. This patch intentionally does not pretend the seam-specific DNS/cert/backup/webmail APIs are complete; it establishes the first plugin container/control-plane surface and records the remaining live integration work as future scope.

Verification:

- Confirmed `go test ./...` passes.
- Added tests for first plugin seams/capabilities, authenticated and unauthenticated gRPC control behavior, Dockerfile plugin runner output, required Compose services, and absence of Docker socket mounts.

### 2026-07-16 01:45 CDT — Add v1 DNS/TLS/ACME diagnostics

Commit: 6b8fa6603a0e47580dbc3c6996c6f9a8397aec2b

Affected files:

- `docs/CHANGELOG.md`
- `internal/diag/dns_tls.go`
- `internal/diag/dns_tls_test.go`
- `workflow.toml`
- `workflow.events.jsonl`
- `workflow/COVERAGE.md`
- `workflow/features/v1.mail-core/dns-tls-acme/evidence/2026-07-16-dns-tls-acme.md`

Explanation:

Completed `v1.mail-core.dns-tls-acme` by adding the diagnostic primitives for exact DNS readiness, TLS certificate validation, MTA-STS/TLS-RPT generation, and loud ACME failure reporting. DNS checks now return the documented status enum with expected values, observed values, and remediation text instead of hand-wavy readiness booleans. TLS checks parse certificates, validate expiry windows, and fail on missing SAN coverage. ACME failure construction is explicit and actionable rather than silently falling back to self-signed behavior.

This is deliberately not the full doctor or live ACME plugin. Those belong to later v1 children. This patch provides the deterministic mechanism and tests they will consume.

Verification:

- Confirmed `go test ./...` passes.
- Added tests for DNS present/missing/mismatch/unsupported states, MTA-STS/TLS-RPT generation, certificate OK/warn/expired/SAN-mismatch behavior, and loud ACME failure output.

### 2026-07-16 01:41 CDT — Generate daemon config for v1 mail core

Commit: d77df0eef449559f03f4075cfe1b35b84590c95c

Affected files:

- `docs/CHANGELOG.md`
- `internal/render/render.go`
- `internal/render/render_test.go`
- `workflow.toml`
- `workflow.events.jsonl`
- `workflow/COVERAGE.md`
- `workflow/features/v1.mail-core/generated-config/evidence/2026-07-16-generated-config.md`

Explanation:

Completed `v1.mail-core.generated-config` by expanding the deterministic render set with daemon-facing generated config files for front/proxy, Postfix, Dovecot, Rspamd, and the selected external webmail provider placeholder. Generated daemon config now points the daemon mechanisms at the v1 internal HTTP/JSON contract endpoints from `v1.mail-core.daemon-contracts` instead of leaving the rendered output as only v0 control-plane/plugin files.

Every generated file now uses the v1 source header form with the generated config set ID and input hash. The render ID is computed from sorted file paths and bodies before source headers are stamped, avoiding a dishonest circular hash while still giving operators traceability from files back to the generated set. Existing staged render/apply behavior remains intact with the larger render set.

Updated workflow state to mark `v1.mail-core.generated-config` done and recorded feature evidence plus the global coverage posture.

Verification:

- Confirmed `go test ./...` passes.
- Confirmed `git diff --check -- .` passes.
- Added render tests proving daemon config files exist and carry `generated_config_set` plus `input_hash` source headers.

### 2026-07-16 01:37 CDT — Implement v1 daemon contract surface

Commit: 824faf10b78352124887aa654bac3f8518ae59fe

Affected files:

- `docs/CHANGELOG.md`
- `go.mod`
- `go.sum`
- `internal/api/api.go`
- `internal/api/api_test.go`
- `internal/daemon/daemon.go`
- `internal/daemon/daemon_test.go`
- `internal/daemon/http.go`
- `internal/daemon/http_test.go`
- `workflow.toml`
- `workflow.events.jsonl`
- `workflow/COVERAGE.md`
- `workflow/features/v1.mail-core/daemon-contracts/evidence/2026-07-16-daemon-contracts.md`

Explanation:

Started v1 mail-core after v0 admission by implementing the first manifest child, `v1.mail-core.daemon-contracts`. This adds the internal HTTP/JSON daemon contract surface used by Postfix, Dovecot, and Rspamd. The implementation uses explicit daemon decisions (`ok`, `not_found`, `reject`, `defer`, `error`), correlation IDs, reason codes, and safe diagnostic messages rather than fake success or stringly hidden failures.

Postfix contract coverage now includes domain, recipient, mailbox, alias, sender-login, sender-policy, rate-limit, and transport behavior. Dovecot coverage now includes passdb, userdb, quota, and default sieve behavior, including Authentik/Django-compatible PBKDF2-SHA256 verifier checks and explicit rejection of OIDC tokens as IMAP/SMTP credentials. Rspamd coverage now includes local domains, DKIM key runtime path lookup, signing decisions, and rate signals. The main API handler now registers the `/internal/v1/postfix/*`, `/internal/v1/dovecot/*`, and `/internal/v1/rspamd/*` routes.

Updated workflow state to make `v1.mail-core.daemon-contracts` the active completed child and `v1.mail-core` in progress. Updated workflow evidence and the global coverage map with the remaining v1 gaps assigned to later planned children.

Verification:

- Confirmed `go test ./...` passes.
- Added contract tests for Postfix happy/failure paths, Dovecot passdb/userdb/quota behavior, Rspamd DKIM/local-domain behavior, malformed JSON/method gates, correlation propagation, and API route wiring.

### 2026-07-16 01:23 CDT — Fix v0 admission blockers from cold review

Commit: 7e6633f

Affected files:

- `cmd/gmf/main.go`
- `cmd/gmf/main_test.go`
- `docs/CHANGELOG.md`
- `go.mod`
- `go.sum`
- `internal/api/api.go`
- `internal/api/api_test.go`
- `internal/apply/apply.go`
- `internal/audit/audit.go`
- `internal/config/config.go`
- `internal/config/config_test.go`
- `internal/plugin/grpc.go`
- `internal/plugin/grpc_test.go`
- `internal/plugin/plugin.go`
- `internal/plugin/plugin_test.go`
- `internal/render/render.go`
- `internal/store/sql.go`
- `internal/store/sql_test.go`
- `internal/store/store.go`
- `migrations/0001_initial.sql`
- `proto/gophermailforge/plugin/v1/plugin.pb.go`
- `proto/gophermailforge/plugin/v1/plugin_grpc.pb.go`
- `workflow/COVERAGE.md`
- `workflow/features/v0.foundation/evidence/2026-07-14-v0-foundation-implementation.md`

Explanation:

Fixed the concrete v0 admission blockers found by cold review instead of merging a stub foundation. The CLI render/diff/apply path now uses real file-backed staged state: render writes a content-addressed staged directory, diff compares the staged set against the currently applied set, and apply requires an operator-provided `--confirm <staged-id>` before marking the generated set as applied. The apply library can now persist the applied marker in the configured applied directory while preserving audit emission.

The HTTP API shell now exposes the required v0 control-plane routes for effective config, render, render diff, render apply, audit event listing, plugin listing, plugin health, status, health/readiness, and authz explain, with method gates instead of silent success. Audit persistence now includes source IP and user-agent fields and a SQL-backed writer that stores redacted before/after payloads. The initial Postgres schema now enforces documented enum/status/seam constraints and rejects enabled plugin registrations without service identity credentials where the database can enforce it directly.

The config loader now uses a real YAML decoder with known-field rejection instead of a hand-rolled colon scanner, including rejection of unknown nested plugin keys. The plugin control transport now uses generated protobuf/gRPC bindings from `plugin.proto`, metadata for correlation/service identity, context deadlines, and canonical gRPC status codes rather than private JSON structs and string errors.

Verification:

- Confirmed `go test ./...` passes after the admission fixes.
- Added regression coverage for staged CLI render/apply confirmation behavior, required API shell routes, SQL audit source persistence, database constraints, YAML unknown-field rejection, and protobuf/metadata/status-code gRPC behavior.

### 2026-07-14 23:59 CDT — Replace SQLite migration harness with embedded Postgres

Commit: 55c9302

Affected files:

- `docs/CHANGELOG.md`
- `go.mod`
- `go.sum`
- `internal/store/sql.go`
- `internal/store/sql_test.go`
- `workflow/COVERAGE.md`
- `workflow/features/v0.foundation/evidence/2026-07-14-v0-foundation-implementation.md`

Explanation:

Corrected the v0 migration test harness after review caught that SQLite was the wrong database target. GopherMailForge's v0 docs and Compose topology use Postgres, and the intended direction is embedded Postgres for local/test verification. SQLite is a different database with different type, constraint, locking, default, and SQL dialect behavior; passing SQLite migration tests would be false confidence.

This change removes the SQLite harness and uses `github.com/fergusstrange/embedded-postgres` plus `github.com/lib/pq` to start a real embedded Postgres instance in the migration test. The test now applies the v0 schema through Postgres, verifies migration-history rows, verifies the domain uniqueness constraint, and verifies mailbox foreign-key rejection against actual Postgres behavior. The migration executor now uses Postgres-style `$1` placeholders.

Verification:

- Confirmed embedded Postgres migration test starts a real local Postgres instance and verifies migration history, unique constraint rejection, and foreign-key rejection.
- Confirmed full `go test ./...` passes.
- Confirmed `sudo docker build -t gophermailforge:v0-smoke .` passes with build-stage tests running as the unprivileged `gmf` user.
- Confirmed `git diff --check -- .` passes.

### 2026-07-15 00:03 CDT — Harden v0 migration and plugin transport tests

Commit: `b36612b3e5aeeed50b1906d082174938887f0cc3`

Affected files:

- `Dockerfile`
- `docs/CHANGELOG.md`
- `go.mod`
- `go.sum`
- `internal/plugin/grpc.go`
- `internal/plugin/grpc_test.go`
- `internal/store/sql.go`
- `internal/store/sql_test.go`
- `workflow/COVERAGE.md`
- `workflow/features/v0.foundation/evidence/2026-07-14-v0-foundation-implementation.md`

Explanation:

Strengthened the v0 foundation implementation after review exposed two weak spots. The first pass had migration coverage that proved the schema list existed but did not execute the schema through a real SQL engine. It also had plugin control behavior as an in-process contract, with the protobuf file present but no actual gRPC transport skeleton test. That was too close to paperwork theater for a foundation release.

This change originally added SQLite-backed migration execution tests using `modernc.org/sqlite`, which was later corrected because the project database contract is Postgres. The gRPC server/client skeleton portion remains: it adds a registered JSON codec over gRPC and `bufconn` tests for authenticated and unauthenticated health calls. The protobuf file remains the contract layout; the transport skeleton now proves the health path crosses a real gRPC boundary instead of only a local function call.

The Go toolchain and Docker builder were aligned to Go 1.25 after dependency resolution raised the module version.

Verification:

- Confirmed `go test ./internal/plugin ./internal/store` passes after the hardening change.
- Full final project verification is recorded in the v0 evidence file and rerun before commit.

### 2026-07-14 23:56 CDT — Record v0 implementation commit hash

Commit: `ca8965fdb74135f19000e3fca8dec0d5f9483a27`

Affected files:

- `docs/CHANGELOG.md`

Explanation:

Updated the v0 implementation changelog entry with the real Git commit hash after Git assigned it. This is the honest way to satisfy the changelog requirement without pretending a commit can contain its own final hash.

Verification:

- Confirmed the v0 implementation entry now records commit `6cf655c37451a8da63e7360e5bde9b7b2664e176`.
- Confirmed `git diff --check -- .` passes.

### 2026-07-14 23:52 CDT — Implement v0 foundation

Commit: `6cf655c37451a8da63e7360e5bde9b7b2664e176`

Affected files:

- `Dockerfile`
- `cmd/gmf/main.go`
- `cmd/gophermailforge/main.go`
- `compose/reference/docker-compose.yml`
- `go.mod`
- `internal/api/api.go`
- `internal/api/api_test.go`
- `internal/apply/apply.go`
- `internal/apply/apply_test.go`
- `internal/audit/audit.go`
- `internal/audit/audit_test.go`
- `internal/authn/authn.go`
- `internal/authn/authn_test.go`
- `internal/authz/authz.go`
- `internal/authz/authz_test.go`
- `internal/config/config.go`
- `internal/config/config_test.go`
- `internal/httpui/httpui.go`
- `internal/plugin/plugin.go`
- `internal/plugin/plugin_test.go`
- `internal/render/render.go`
- `internal/render/render_test.go`
- `internal/store/store.go`
- `internal/store/store_test.go`
- `internal/version/version.go`
- `migrations/0001_initial.sql`
- `proto/gophermailforge/plugin/v1/plugin.proto`
- `test/contract/sample-config.yaml`
- `test/contract/v0_contract_test.go`
- `test/fixtures/mail.crt`
- `test/fixtures/mail.key`
- `workflow/COVERAGE.md`
- `workflow.events.jsonl`
- `workflow.toml`
- `workflow/features/v0.foundation/evidence/2026-07-14-v0-foundation-implementation.md`

Explanation:

Implemented the v0 foundation as a narrow control-plane baseline. This adds the Go module, server and CLI entrypoints, HTTP/API health/status/authz shell, GOTTH-compatible server-rendered UI shell, typed config parser and validator, TLS safety validation, deterministic render output, explicit apply gate, audit writer and redaction, static v0 authorization simulator, Authentik base model, initial schema/migration representation, plugin registry/control skeleton, protobuf contract layout, Dockerfile, reference Compose topology, contract fixtures, tests, workflow evidence, coverage updates, and workflow state updates for v0.

The implementation intentionally does not add v1 mail-daemon behavior, SCIM provisioning, full OIDC login, real plugin implementations, or custom webmail. v0 remains the foundation: it establishes package boundaries, validation, audit/authz behavior, render/apply mechanics, plugin contract seams, Authentik-adjacent topology, and verification harnesses.

The workflow manifest now marks `v0.foundation` and its v0 child features as done. Evidence for the verification commands and coverage posture is recorded under `workflow/features/v0.foundation/evidence/`.

Verification:

- Confirmed `go test ./...` passes.
- Confirmed explicit binary builds for `cmd/gmf` and `cmd/gophermailforge` pass.
- Confirmed CLI config validation, render, diff, apply, migrate, and authz smoke commands pass against `test/contract/sample-config.yaml`.
- Confirmed `sudo docker build -t gophermailforge:v0-smoke .` passes and runs `go test ./...` inside the build stage.
- Confirmed `git diff --check -- .` passes.

### 2026-07-14 23:31 CDT — Expand changelog entry requirements

Commit: `9d84ad3aa567a9579c73afb4c4b74b686ea9ec6c`

Affected files:

- `docs/CHANGELOG.md`
- `docs/implementation/IMPLEMENTATION.md`
- `workflow/README.md`
- `workflow.toml`

Explanation:

The first changelog pass was too terse. It recorded that a change happened, but it did not force the entry to carry enough review context. That is sloppy for a project that is using PRDs, architecture, implementation specs, workflow evidence, and detached worktrees as serious state. A changelog that only says "changed things" is decoration, not audit value.

This change makes the changelog format explicit. Each meaningful change now needs a date/time with timezone, commit identifier, affected files, verbose explanation, and verification summary. The rule also documents the unavoidable Git self-reference problem: the entry for the commit currently being created cannot contain its own final hash because the hash depends on the file content. Historical entries must use real hashes.

Verification:

- Confirmed verbose changelog fields are present.
- Confirmed markdown links resolve.
- Confirmed `workflow.toml` parses and points to `docs/CHANGELOG.md`.
- Confirmed `git diff --check -- .` passes.

### 2026-07-14 23:27 CDT — Add docs changelog discipline

Commit: `1dd7d7fff82940cfafc4934242631eafb68642ad`

Affected files:

- `README.md`
- `docs/CHANGELOG.md`
- `docs/implementation/IMPLEMENTATION.md`
- `workflow.toml`
- `workflow/README.md`

Explanation:

Added the project changelog under `docs/` and made it part of the documented development workflow. The repository already had PRDs, architecture docs, implementation specs, workflow records, and evidence folders, but it lacked a compact chronological index of meaningful changes. That was a real gap: reviewers would have to reconstruct project history from scattered commits and workflow artifacts.

The change links the changelog from the root README, adds implementation-level discipline requiring changelog updates for meaningful changes, records the changelog path in `workflow.toml`, and explains in `workflow/README.md` that workflow evidence remains separate from the changelog. The changelog is the human-readable index; it is not a substitute for tests, evidence, handoff notes, or verification.

Verification:

- Confirmed `docs/CHANGELOG.md` exists.
- Confirmed markdown links resolve.
- Confirmed `workflow.toml` parses.
- Confirmed `git diff --check -- .` passes.
- Fast-forwarded all six root worktrees to the commit.

### 2026-07-14 23:19 CDT — Require Authentik-compatible password hashes

Commit: `653b9e7a7e69cd2feaadd9c8abd82625e9ebe377`

Affected files:

- `README.md`
- `docs/architecture/v2-identity-provisioning.md`
- `docs/implementation/IMPLEMENTATION.md`
- `docs/implementation/v0-foundation.md`
- `docs/implementation/v1-mail-core.md`
- `docs/implementation/v2-identity-provisioning.md`
- `docs/implementation/v3-ops-import-admin.md`
- `docs/prd/PRD-v2-identity-provisioning.md`
- `docs/prd/PRD.md`
- `docs/reference/authentik-password-hashing.md`
- `workflow.toml`

Explanation:

Verified Authentik's actual password hashing behavior instead of guessing from dependency names. Source inspection showed Authentik uses Django 5.2 password hashing, does not define a project-local `PASSWORD_HASHERS` override in `authentik/root/settings.py`, validates imported password hashes with Django `identify_hasher(password_hash)`, and hashes passwords with Django `make_password(password)`. Django stores password hashes as encoded strings carrying the algorithm and parameters, such as `algorithm$iterations$salt$hash`; the default new-password hasher is PBKDF2-SHA256 unless configured otherwise.

The GopherMailForge specs were updated so mailbox-password and app-password/mail-client verifier storage must use Authentik-compatible Django encoded password-hash strings where password sync or Dovecot verification is intended. This rejects a private mail-only password hash scheme. The Dovecot passdb path must verify submitted secrets against the same stored verifier string. Imports and synchronization must reject plaintext, unknown algorithms, deprecated algorithms, or policy-disabled algorithms unless a documented migration exception exists.

This keeps Authentik adjacent rather than embedded: Authentik compatibility defines the verifier format, but Authentik outage must not become a runtime dependency for IMAP/SMTP authentication of already-stored verifiers.

Verification:

- Confirmed markdown links resolve.
- Confirmed `workflow.toml` parses.
- Confirmed `git diff --check HEAD~1..HEAD` passes.
- Fast-forwarded all six root worktrees to the commit.
