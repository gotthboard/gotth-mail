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
Groups and session revocation remain unavailable until the authoritative
Authentik-subject binding exists; no ID-token claim substitutes for it.

The current email-address-as-resource-ID scheme requires an explicit migration
and Authentik adoption proof. It must not be silently reinterpreted.

## Compatibility proof in this feature

This release-contract feature pins both libraries and runs an external
consumer contract test that performs a real OIDC discovery/begin request and a
real SCIM User create/read cycle. That proves dependency and public-API
compatibility only. The later identity feature now supplies the consumer-owned
PostgreSQL adapter and runtime cutover. Live Authentik, legacy adoption,
backup/restore, and release promotion remain separate blocking evidence.

## Release verification

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
