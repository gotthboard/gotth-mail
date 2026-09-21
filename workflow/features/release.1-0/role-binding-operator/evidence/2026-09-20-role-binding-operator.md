# Role-binding operator verification — 2026-09-20

## Exact candidate

- contract: `09445d3846baa5e613769bce7fadc37e770ee34b`;
- implementation: `8724af64e5f989136bc57e5e4ee0fdd407b16517`;
- closed input boundary: `1db0abe3db01aebcbded2cda2deae34d7967dde0`;
- final test candidate: `d29f0e18fe8437d30ed100788f2a9dbb65293539`.

## Mechanism

`gotth-mailctl identity role-binding` accepts only `preview` or `apply`, a
closed flag set, one exact HTTPS Authentik issuer path, one opaque subject, one
canonical mailbox, and one admitted role/domain shape. Apply recomputes the
plan inside a serializable transaction after locking the identity, mailbox,
mailbox domain, target domain, and any existing binding. A stale or malformed
32-byte confirmation digest fails before mutation.

Migration `0018_role_binding_authority` rejects inconsistent or duplicate
existing authority rather than rewriting it. Partial unique indexes and a
role/domain check enforce global and scoped cardinality at the database layer.
Grant/revoke and the redacted audit event commit atomically. Existing sessions
read the durable binding immediately; a fresh store instance reads the same
state. Revoke remains available after disabled state.

## Verification

- `go test ./...` — passed;
- `go test -race ./...` — passed;
- `go vet ./...` — passed;
- `go build ./cmd/...` — passed;
- `go test -race -count=20 -shuffle=on ./internal/rolebinding ./cmd/gotth-mailctl`
  — passed;
- focused PostgreSQL tests cover all three roles, global/scoped constraints,
  exact identity selection, no-op behavior, stale confirmation, concurrent
  grant, injected audit failure rollback, disabled grant rejection,
  revoke-after-disable, existing-session projection, and CLI end to end;
- focused coverage: `internal/rolebinding` 86.7%; new CLI request parser 100%.
  The remaining service statements are injected database/commit/row-count and
  entropy failure branches. They are recorded as a coverage gap; the material
  failure paths—stale state, concurrent serialization, and atomic audit
  rollback—are directly exercised;
- clean clone of exact candidate `d29f0e1` passed store, role-binding, and CLI
  tests;
- production build-contract rejection checks passed;
- `git diff --check` and clean worktree checks passed before evidence.

## Limits

This admits a local operator mechanism. It does not create the first live
administrator, alter a live database, configure Authentik, publish an image or
release, change DNS, or prove a deployed login. Those remain integration and
owner-acceptance work.
