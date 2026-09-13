# Architecture — 1.0 release line

Source PRD: [PRD-release-1.0.md](../prd/PRD-release-1.0.md)

## Release state machine

```text
development -> 1.0.0-alpha.N -> 1.0.0-beta.N -> 1.0.0
```

Alpha promotion requires a reproducible integrated artifact and exact source
identity. Beta promotion additionally requires every stable-1.0 capability to
exist and its migrations to be forward-safe. Stable promotion requires the
complete deployed acceptance matrix and owner approval. A failed candidate is
left immutable and replaced by a higher prerelease number.

The historical workflow roots named `v0.*` through `v5.*` are capability
workstreams, not release branches. Renaming their IDs would sever evidence and
worktree history, so only their human-facing titles and the release contract
change.

## Identity composition

### OIDC

GOTTH Mail imports `github.com/gotthboard/gotth-oidc/pkg/oidc` for discovery,
authorization-code plus PKCE, protected attempt material, exchange, and token
verification. The application persists the protected attempt with its browser
binding and redirect target, consumes it atomically, maps the verified subject
to product identity, creates the application session, and resolves roles from
consumer-owned provisioned state. OIDC claims are not granted direct mailbox
or administrator authority.

### SCIM

GOTTH Mail imports `github.com/gotthboard/gotth-scim/pkg/scim` for the SCIM
server and protocol behavior. A GOTTH Mail adapter implements the library's
transaction-bearing `Store` contract over the canonical database. Request
authentication happens before the SCIM handler; `ResolveScope` maps the
authenticated provisioning client to an opaque scope. Password changes use
the optional atomic password transaction and never enter resource JSON or
logs.

The adapter projects admitted SCIM Users into mailbox and domain state through
the existing authorization and audit services, then updates the single
process's daemon/passdb view after commit. SCIM Groups, role projection, and
web-session invalidation remain disabled until opaque User membership is bound
to authoritative Authentik OIDC subjects. SCIM resource IDs are opaque and
persistent; email addresses remain mutable indexed attributes. A legacy
migration must preserve provider IDs or record a deliberate one-time adoption
mapping.

The composition point is the database, not a provider-specific token parser.
The exact verified OIDC subject must equal one active SCIM User `externalId`,
and the verified email must equal that User's projected mailbox. The resulting
identity reference owns the session; a SCIM disable/delete revokes it in the
same transaction as deprovisioning.

## Failure boundaries

- OIDC or SCIM unavailability blocks new login/provisioning; it never blocks
  established SMTP delivery or daemon lookups.
- A callback is rejected if its protected attempt cannot be consumed exactly
  once or its browser binding fails.
- A SCIM transaction rolls back if product validation, authorization, password
  delegation, audit, or persistence fails.
- Duplicate in-tree protocol code is removed only with route-compatible
  consumer tests; live Authentik integration still blocks promotion.
- Missing GitHub distribution, library license decisions, or exact dependency
  provenance blocks release promotion but does not weaken runtime checks.

## Rollback

Each alpha/beta deployment retains the preceding application artifact,
configuration generation, database backup, and exact dependency lock. Schema
rollback is claimed only when rehearsed; otherwise rollback restores the paired
backup and prior artifact. Tags and failed candidates are never moved.
