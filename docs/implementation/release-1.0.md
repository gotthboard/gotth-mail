# Implementation Spec — 1.0 release line

Source PRD: [PRD-release-1.0.md](../prd/PRD-release-1.0.md)
Source architecture: [release-1.0.md](../architecture/release-1.0.md)

## Version grammar

Build identity is exactly one of:

- `dev` for an untagged development build;
- `1.0.0-alpha.N`, where `N` is a positive decimal without leading zeroes;
- `1.0.0-beta.N`, under the same numeric rule; or
- `1.0.0` after stable admission.

Git tags add the conventional `v` prefix. `v1.0.0-alpha.1` therefore embeds
`1.0.0-alpha.1`. Release builds set
`forgejo/gotthboard/gotth-mail/internal/version.Version` with `-ldflags -X`,
then run `gotth-mailctl version` and compare the exact result to the tag.
The control-plane status API and plugin Version RPC expose the same linked
identity. Every executable rejects an invalid linked version before serving or
mutating state.

## OIDC adoption

Pin `github.com/gotthboard/gotth-oidc` to an immutable reviewed revision. The
consumer adapter must:

1. construct one client from the exact issuer, client, redirect, endpoint
   policy, and bounded transport;
2. persist `ProtectedAttempt` plus browser-binding hash, redirect target,
   creation time, and expiry;
3. locate and atomically consume the attempt by the callback state's SHA-256
   hash before accepting completion;
4. map only verified issuer/subject/profile identity into the product identity
   record;
5. resolve authorization roles from durable provisioned mappings rather than
   treating arbitrary token claims as authority; and
6. create/rotate the application session with no token disclosure.

Session creation additionally requires an exact active SCIM User binding:
OIDC subject equals SCIM `externalId`, verified email equals projected mailbox,
and the resulting identity reference is foreign-keyed by the session. Missing
or ambiguous candidates fail closed. SCIM deprovisioning revokes dependent
sessions transactionally.

Existing public login and callback URLs remain unchanged during cutover.

## SCIM adoption

Pin `github.com/gotthboard/gotth-scim` to an immutable reviewed revision. The
consumer adapter must implement `scim.Store`, pass `scim.CheckStore`, and use a
single database transaction per library callback. It must defensively copy
record bytes and indexes, enforce opaque persistent resource IDs, uniqueness,
tombstones, expected versions, and immediate deletion visibility.

Authentication middleware validates the verifier-backed SCIM bearer before
the library handler. `ResolveScope` returns only the authenticated client's
opaque provisioning scope. Canonical resource, mailbox, authorization, success
audit, and password delegation changes commit or fail together with the SCIM
transaction. The admitted single control-plane writer updates its in-memory
daemon/passdb view only after commit and reconstructs it from SQL on restart.
Groups are non-authoritative provisioning inventory whose members must be
same-scope opaque User IDs. Group mutations create no role authority. User
disable/delete revokes bound sessions transactionally. Stable Group-to-role
projection remains unavailable until the live Authentik profile and exact
mapping are admitted; no ID-token claim substitutes for it.

Legacy email-keyed mailboxes use the implemented redacted preview plus exact
digest-confirmed adoption path. The `gotth-scim.Reconciler` owns validation and
opaque ID generation; the product transaction preserves mailbox UUID,
verifier, enabled state, and mail ownership. No OIDC identity or session is
fabricated. Live Authentik adoption proof remains required.

## Compatibility proof in this feature

This release-contract feature pins both libraries and runs an external
consumer contract test that performs a real OIDC discovery/begin request and a
real SCIM User create/read cycle. That proves dependency and public-API
compatibility only. The later identity feature now supplies the consumer-owned
PostgreSQL adapter and runtime cutover. Durable login attempts and sessions,
OIDC-to-SCIM binding, session-bound app-password self-service, reviewed legacy
adoption, and non-authoritative opaque Groups are implemented and evidenced.
Live Authentik, stable Group-to-role projection, identity-aware backup/restore,
and release promotion remain separate blocking evidence.

## Extensions foundation adoption

Pin an immutable reviewed `gotth-extensions` revision. Replace or reconcile
only the existing duplicate plugin control mechanics: manifest validation,
host grant, version negotiation, lifecycle validation, handshake, and health.
Mail's DNS, notification, backup, webmail, certificate, and import operations
remain separate versioned protocols.

The admitted consumer pin is
`v0.0.0-20260914032833-3822dd722bc8`. Each existing built-in mechanism keeps
its Mail-owned seam RPC and receives a deterministic instance identity plus an
exact foundation manifest, grant, negotiated session, and validated lifecycle.
The consumer-local `gotth.extensions.v1.ExtensionControl` binding preserves the
reviewed upstream wire contract and changes only its Go package location.
Plugin processes expose authenticated challenge-bound handshake and
session-bound health beside the existing Mail control RPCs; production
notification health uses the foundation exchange. No generic payload,
callback, process-control, event-bus, or product-mutation method is added.

The administrator implementation is governed by the v3 operations
specification. No extension-provided HTML, JavaScript, templ component,
Tailwind class list, CSS, redirect, or arbitrary action is admitted. Every
installed artifact, manifest digest, grant, transport identity, configuration
revision, and rollback pin is independently recorded and audited.

## Same-domain-only outbound integration

Implement the v1 mail-core per-domain outbound-scope contract before alpha
integration. The feature is complete only when durable policy/revision state,
preview/confirm administration, daemon decisions, generated Postfix wiring,
submission and expansion enforcement, queue disposition/re-evaluation, audit,
backup/restore, and operator diagnostics are proven together. Unit-only or
header-only checks are not admissible evidence.

The current live-identity feature retains the single active workflow slot.
Once that boundary is handed off, this owner-prioritized feature is the next
implementation assignment before lower-priority new feature work.

## Release verification

### Production artifact implementation

`build/production` owns five role Dockerfiles, fixed entrypoints, native
configuration checks, and deterministic artifact assembly. Builds require
`VERSION`, `SOURCE_COMMIT`, and `BUILD_DATE_EPOCH`; release builds reject dirty
source and development identity. Every image sets exact OCI version/revision
labels and `com.gotth.mail.role`, uses the fixed
`/usr/local/bin/gotth-mail-entrypoint`, and contains
`/usr/local/bin/gotth-mail-health`.

`cmd/gotth-mail-release` builds the strict canonical release manifest and
configuration USTAR without invoking Docker or accessing the network. Input
is a closed typed release specification. Archive members are sorted regular
files with UID/GID zero, mode 0440, USTAR format, epoch mtime, no links, and no
extended metadata. The command hashes the exact archive bytes and every
member, refuses unknown or reference-only files, and writes atomically.

The front-auth endpoint accepts only the NGINX mail-module header contract,
bounds every header, redacts credentials from logs/errors, validates mailbox
credentials through the canonical daemon/passdb service, enforces unauthenticated
SMTP recipient policy, and returns only fixed private backend names/ports.
Its service credential is file-backed; no password, token, key, or DSN enters
image metadata, Docker arguments, or plaintext environment values.

The release gate builds every role twice, compares configuration/manifest and
binary digests, inspects effective image labels/user/entrypoint/packages, runs
native config checks, starts all roles on a disposable private network, proves
TLS/STARTTLS/auth/proxy behavior, and then runs Stack replacement/rollback.
The existing reference Compose and Telegram fixtures are forbidden inputs.

- version grammar unit tests, including rejected zero, leading-zero, `0.x`,
  `v`-prefixed build strings, and release-candidate forms;
- exact public-module pseudo-version or tag pins in `go.mod`/`go.sum`;
- OIDC and SCIM external-consumer compatibility test;
- consumer adapter conformance, migration, race, restart, backup, and restore
  tests before beta;
- live Authentik browser login, provisioning, role, deprovisioning, and replay
  rejection before beta;
- full/race/vet/build/container, deployment, rollback, security,
  accessibility, monitoring, and owner-acceptance gates before stable.
- extension-foundation conformance plus administrator setup/test/enable/
  disable/update/rollback, secret-redaction, hostile-metadata, and failure-
  isolation tests before beta.
- same-domain-only outbound hostile-path tests across SMTP, webmail/API,
  expansions, automated mail, retry/replay, restored queues, and final transport
  before alpha integration may publish.
