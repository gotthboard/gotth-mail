# Legacy mailbox adoption evidence — 2026-09-13

## Admitted mechanism

- `gotth-mailctl identity adopt preview|apply` reads the configured PostgreSQL
  store and requires mailbox, Authentik subject, SCIM scope, manager, and an
  exact preview digest for apply.
- Preview is deterministic and redacted. It binds the mailbox UUID, normalized
  address, display name, enabled state, creation/update versions, subject,
  scope, manager, and any exact existing ownership; it contains no verifier.
- Apply uses the exact pinned `gotth-scim.Reconciler`. The library validates
  the User document, enforces manager/external-ID semantics, preserves
  tombstones, and generates the opaque resource ID.
- A transaction-local product claim locks one exact unowned legacy mailbox.
  The SQL adapter preserves its UUID, verifier, creation time, enabled state,
  and mail ownership while attaching the generated SCIM ID and admitting the
  standard redacted SCIM audit in the same serializable transaction.
- A global subject-ownership predicate is rechecked inside the transaction so
  separate SCIM scopes cannot race into an ambiguous OIDC subject.
- An exact repeat goes through the reconciler and returns the same resource;
  different ownership and malformed ownership records fail closed.
- Adoption creates no `identity_refs`, session, or role binding. A verified
  `gotth-oidc` issuer/subject/email callback remains mandatory.

## Verification

Development host, final implementation head `1dbda59fc00338df54d0f0a6dd83175814fbac44`:

- focused PostgreSQL packages twice: pass
- targeted race tests for adoption, SCIM store, and CLI: pass
- `git diff --check` and clean worktree: pass

Development host, immediately preceding review-fix head
`7098b7d68386004e6cbe16c205cf5224a10b017e`:

- full `go test ./...`: pass
- full `go test -race ./...`: pass
- `go vet ./...`: pass
- all three command builds: pass
- `go mod verify`: pass

Coverage:

- `internal/identityadopt`: 79.8% statement coverage
- cross-package adoption run exercises 75.0% of `mailboxFromRecord`; the
  adoption branch of `persistMailbox`, the confirmation comparison, restart,
  stale state, ownership conflict, tombstone, and audit rollback paths execute
  against PostgreSQL
- remaining uncovered paths are defensive database, JSON encoder, and random
  entropy failures. They are recorded rather than disguised as 100%.

Code graph:

- Graphify 0.9.32 code-only extraction
- 1,800 nodes / 5,388 edges
- graph SHA-256:
  `13fde2b740fbec1f8a787400dca7082c2d640368d3837f2bb640958697d5212b`
- three potential secret fixtures were skipped; six SQL files were omitted by
  the optional SQL parser and were instead exercised by PostgreSQL tests

## Remaining boundary

This closes only legacy mailbox adoption. The live `gotth-mail` Authentik
issuer/profile, browser/passkey login, installed-provider provisioning and
deprovisioning, durable role/Group projection, backup/restore proof, GitHub
mirror, tags, deployment, beta, and stable 1.0 remain open. Product `main` was
not touched.
