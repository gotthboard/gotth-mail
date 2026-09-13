# GOTTH Mail 1.0 alpha — protected OIDC runtime evidence

Date: 2026-09-13

Branch: `workflow/feature/v2.identity-provisioning.oidc-sessions`

Base development revision: `21b5ff6876624fc0e14532d636f7d12d92d442b6`

Documentation prerequisite: `819c47dbf47d19ec3a7fe750d3d5604f3ec5b16f`

## Scope

This candidate replaces only the OIDC protocol boundary and its required
durability wiring. It does not admit SCIM, role mapping, app passwords, a
release tag, product `main`, deployment, or stable behavior.

The removed in-tree code performed discovery, JWKS parsing, Authorization Code
construction, token exchange, and ID-token validation itself. The candidate
uses the exact pinned `github.com/gotthboard/gotth-oidc/pkg/oidc` revision for
those mechanisms and retains only consumer-owned storage, browser binding,
local return path, session, cookie, and identity mapping.

## State and failure behavior

- `oidc_login_states` stores the library's 32-byte state digest, fixed-size
  encrypted nonce and PKCE envelopes, bounded authenticated context, a
  32-byte independent browser-binding digest, local return path, and times.
- Raw state, nonce, PKCE verifier, authorization code, and tokens are not
  persisted by GOTTH Mail.
- One conditional `UPDATE ... RETURNING` consumes an attempt before external
  exchange. A replay, concurrent loser, wrong browser, or expired attempt
  receives `ErrInvalidOIDCState`. Exchange failure leaves the attempt spent.
- ID-token group claims are no longer admitted into authorization. The
  provider-neutral identity contains issuer, subject, display name, and only a
  library-verified email.
- Migration `0003_oidc_protected_attempts` deletes legacy in-flight attempts,
  preserves sessions, and installs size/order constraints. Migration `0001`
  and its frozen checksums remain unchanged.
- Runtime OIDC refuses volatile storage. PostgreSQL is opened, pinged,
  migrated, and loaded before provider discovery; direct and `_FILE` secret
  sources are mutually exclusive.

## Cost model

Login begin performs the library's bounded fixed-size cryptography plus one
database insert. Callback performs one state-hash lookup/conditional update,
one provider exchange/verification, and one session insert. Stored secret
envelopes are fixed-size except for the bounded 65,536-character authenticated
context. No queue, polling loop, additional serialization layer, or async
projection was introduced.

## Verification

Development host candidate: `/tmp/gotth-mail-oidc.ts6ZAT`

- focused real-PostgreSQL suites passed for `internal/authn`, `internal/store`,
  `internal/api`, and `cmd/gotth-mail`;
- an eight-consumer PostgreSQL callback race admitted exactly one winner;
- legacy baseline upgrade, fresh install, idempotence, ledger rejection,
  protected-column shape, in-flight invalidation, and session preservation
  passed;
- runtime database migration/service wiring and OIDC discovery configuration
  passed;
- `go test -p=1 -count=1 -coverprofile=... ./...` passed;
- `go test -race -count=1 ./...` passed;
- `go vet ./...`, all three command builds, `go mod verify`, and
  `git diff --check` passed;
- `internal/authn` statement coverage is 93.3%; every new memory-store
  operation and `StartLogin` are 100%, `CompleteCallback` is 90.5%, and the
  SQL concurrency/migration paths are exercised against PostgreSQL;
- the first parallel coverage run exposed one existing notification socket
  reset and one test-PostgreSQL free-port collision. Each exact test passed ten
  consecutive isolated runs; the serialized repository coverage gate then
  passed. They are recorded rather than hidden as a clean rerun.

Graphify 0.9.32 rebuilt the code-only graph at
`/home/linus/.cache/openclaw-graphify/gotth-mail/oidc-protected-candidate/graphify-out/graph.json`.
SHA-256:
`6e987161633ccd136e0b4b3968effb7c5c10ea81be71ff248c0efef1ec59faed`.
It contains 1,645 nodes, 3,984 edges, and 88 communities. Three
sensitive-looking fixture/key files were skipped without inspection or
disclosure. SQL was omitted because the optional parser is absent; no package
was installed. The generated repository-local cache was removed after
extraction; no Graphify artifact is admitted to Git.

## Cold review verdict

Accepted with constraints. The post-fix review found no new blocker inside the
OIDC slice. Duplicate state insertion now fails instead of overwriting an
attempt, secret-file reads are bounded, valid provider error callbacks consume
their attempt, and the loaded SQL identity service binds to the handler's
daemon instance. Existing readiness and SQL-session error-reporting limits are
broader operations work and are not disguised as part of this admission.

## Remaining admission gates

- commit, Forgejo PR, and target-branch admission;
- live Authentik browser/passkey callback proof;
- GitHub mirror remains an independent distribution/release blocker.
