# gotth-scim PostgreSQL runtime evidence

Feature: `v2.identity-provisioning.scim`
Timestamp: 2026-09-13 16:29 CDT

## Scope

Replace the handwritten runtime SCIM protocol surface with the exact pinned
`github.com/gotthboard/gotth-scim/pkg/scim` API and supply the consumer-owned
PostgreSQL, authentication, authorization, mailbox, password, audit, and daemon
projection mechanisms.

## Mechanism

- `gotth-scim.Server` owns service metadata, schemas, Users HTTP behavior,
  bounded parsing, PATCH/search semantics, ETags, opaque IDs, tombstones, and
  write-only password dispatch.
- `internal/scimstore.SQLStore` implements `scim.Store`, `scim.Transaction`,
  `scim.PasswordStore`, and `scim.PasswordTransaction` over migration `0004`.
- Every accepted User mutation, optional password verifier update, mailbox
  projection, and success audit event commits in one serializable PostgreSQL
  transaction. The library callback is invoked exactly once.
- Every request authenticates a durable `scim_client` token. Its stable actor
  ID derives an opaque storage scope; secret rotation must retain that ID.
- The process-local daemon/passdb view updates after commit and is rebuilt from
  SQL on startup. The admitted runtime topology remains one control-plane
  writer; horizontal cache propagation is not implemented.
- Groups fail with `501` until opaque member IDs and authoritative Authentik
  OIDC-subject binding exist. Legacy email-keyed mailboxes are not guessed into
  SCIM ownership.

## Hostile findings repaired during focused verification

1. PostgreSQL timestamp columns truncated nanoseconds required by the imported
   record contract. Migration `0004` now stores exact integer nanoseconds.
2. Index rows lost their library-defined order. An explicit ordinal now
   preserves exact conformance round trips.
3. The test client used generic JSON instead of `application/scim+json`; tests
   now exercise the real media-type contract.
4. A restarted identity service loaded SQL before daemon binding, leaving
   passdb empty. Binding now deterministically rebuilds mailbox/app-password
   projections.
5. The executable routed only `/api/`, so `/scim/` would have fallen into the
   UI. The runtime mux now sends `/scim/` to the API server, with a regression
   test.
6. The durable identity loader rebuilt users and tokens but not the enabled
   domain allowlist, which would have admitted an arbitrary syntactically
   valid domain after restart. Startup now loads enabled domains from SQL and
   rejects disabled or unmanaged domains. An empty SQL allowlist denies every
   domain; only deliberately domainless in-memory fixtures remain permissive.
7. Mailbox rename moved the opaque SCIM resource but left the old daemon entry
   and email-keyed app-password ownership behind. Rename now moves app-password
   ownership in the same SQL transaction, removes the old process projection,
   and preserves the credentials at the new address across restart.

## Final verification

- exported `scim.CheckStore` passes against real PostgreSQL;
- focused SCIM store, API, command-routing, migration, identity, and daemon
  suites pass on the development host;
- product tests cover authentication, opaque IDs, create/list/read/replace/
  patch/disable, write-only passwords, restart, tombstone reservation, rename,
  malformed/scalar/unsupported input, Groups rejection, audit failure rollback,
  and concurrent uniqueness;
- repository compile-only checks and `git diff --check` pass locally.
- development-host `go test -count=1 ./...` passes;
- development-host `go test -race -count=1 ./...` passes. The first race run
  hit one temporary PostgreSQL listener startup failure in the unrelated
  `internal/ops` package; its isolated rerun and the complete clean rerun both
  passed;
- serialized repository coverage passes at 66.4% statements; cross-package
  API plus store coverage measures 77.0% of `internal/scimstore` statements;
- `go vet ./...`, all three command builds, and `go mod verify` pass;
- Graphify 0.9.32 rebuilt a code-only graph at 1,726 nodes, 4,179 edges, and
  89 communities. Graph SHA-256:
  `e7f242263e9e80b6704d0b3bfee912e334992f284d591b5aef72b12691544b04`.
  Three fixture secret/certificate files were skipped without inspection;
  four SQL files were absent from the graph because the optional SQL parser is
  not installed, so the migration was reviewed and tested directly. The
  repository retained no generated graph artifact.

## Coverage and remaining gates

No accepted functional gap exists in the changed success, policy, rollback,
restart, rename, password, tombstone, or concurrency behavior. Literal 100%
statement coverage is not claimed: remaining store branches are primarily
database-driver/row-scan/cryptographic-random failure legs that would require
an injected SQL driver or fake entropy source. The real audit-constraint
failure test already proves whole-transaction rollback rather than merely
executing one fabricated error line.

Live Authentik lifecycle, authoritative subject binding, operator-controlled
legacy adoption, and isolated backup/restore proofs remain feature/root gates
and are not fabricated here. Product `main` and production deployment are not
part of this slice.

Cold post-fix review found no remaining slice-level blocker. Admission is
acceptable only into the unfinished 1.0-alpha development line with the
single-writer, disabled-Groups, legacy-adoption, and live-proof constraints
preserved.
