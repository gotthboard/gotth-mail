# SCIM Client-Token Bootstrap Evidence — 2026-09-13

Feature: `v2.identity-provisioning.live-authentik-persistence`

Branch: `workflow/feature/v2.identity-provisioning.scim-token-bootstrap`

Base unfinished line: `f894ac8f44fd71c2da2691057ccdd8601ea1e3c9`

Reviewed implementation head: `7fb2a03` (evidence commit follows)

## Problem

The GOTTH Mail SCIM endpoint already required a verifier-backed
`scim_client` bearer, but no supported operator path could create or rotate
that credential in PostgreSQL. Consequently, configuring Authentik's outbound
SCIM provider would have required an undocumented direct database write. That
is not an admissible identity boundary.

The installed Authentik 2026.5.2 source was inspected before design. Its
outbound `SCIMProvider` requires a base URL, token authentication, TLS
verification, user/group property mappings, sync scope, and optional
backchannel application. The live installation has no SCIM provider, and no
GOTTH Mail runtime or public `/scim/v2` endpoint currently exists.

## Admitted mechanism

`gotth-mailctl identity scim-token preview|apply` now:

- accepts one 32-512 byte bearer only through a regular final non-symlink file
  owned by the effective user with no group/world permission bits;
- rejects whitespace, control bytes, non-bearer-safe data, unsafe IDs, direct
  argv secret input, kind collisions, and malformed stored verifiers;
- emits only a plan digest, stable actor ID, and operation;
- binds confirmation to requested secret digest and current verifier/revocation
  state;
- locks and rechecks the exact stable token row in a serializable transaction;
- stores only a Django PBKDF2-SHA256 verifier;
- commits create/rotate/reactivate with a redacted audit event atomically;
- performs no verifier or audit write when the same active secret is supplied;
  and
- preserves the stable actor ID used by GOTTH Mail to derive the opaque SCIM
  provisioning scope.

The operator-owned secret file remains the transfer source for Authentik.
Neither plan/apply JSON nor audit records contain the bearer, verifier, secret
file path, or secret digest.

## Hostile verification

Development host worktree:

`/tank/development/linus/gotth-mail-worktrees/v2.identity-provisioning.scim-token-bootstrap`

At `e194203` after the final runtime repair:

- focused PostgreSQL tests: pass;
- focused race tests: pass;
- full `go test -count=1 ./...`: pass;
- full `go test -count=1 -race ./...`: pass;
- `go vet ./...`: pass;
- all three command builds: pass;
- `go mod verify`: pass;
- pinned `gotth-authentik` profile verification: pass;
- every shell script syntax check: pass;
- clean worktree and `git diff --check`: pass.

At test-only head `7fb2a03`:

- focused PostgreSQL tests: pass;
- focused race tests: pass;
- end-to-end `gotth-mailctl` preview/apply against migrated PostgreSQL: pass;
- `internal/scimtoken` statement coverage: 89.7%; and
- clean worktree and `git diff --check`: pass.

The uncovered statements are defensive failures that require injected kernel,
`database/sql`, entropy, JSON-marshal, or transaction-commit faults. Adding a
fake database abstraction solely to make those lines green would make the
credential path harder to trust. Real mutation, validation, rollback,
idempotency, stale-state, and corrupt-state branches are covered.

## Review repair

Cold review rejected the first implementation because a malformed stored
verifier was treated as a normal secret mismatch. That would have allowed a
rotation to overwrite corrupt state without surfacing it. The admitted code
validates the stored PBKDF2 structure first and fails closed. The same review
added effective-user ownership enforcement and exact affected-row checking.

## Deliberate non-claims

- No live SCIM bearer was generated or installed.
- No Authentik SCIM provider was created.
- No GOTTH Mail runtime or public callback/SCIM endpoint was deployed.
- No live user, mailbox, Group, role, or session was changed.
- The historical `gophermailforge` provider was not retired.
- Product `main`, tags, releases, and the postponed GitHub mirror were not
  changed.

The next live gate requires an owner-selected public HTTPS GOTTH Mail URL and
deployment target. Only then can the same protected bearer be admitted into
GOTTH Mail, installed into Authentik, and exercised through provision, login,
disable, deprovision, restart, backup, restore, and rollback.
