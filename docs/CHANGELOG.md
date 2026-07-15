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

### 2026-07-14 23:52 CDT — Implement v0 foundation

Commit: current commit; hash assigned by Git after commit

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
