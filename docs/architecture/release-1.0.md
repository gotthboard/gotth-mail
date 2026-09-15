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
process's daemon/passdb view after commit. SCIM Groups are durable,
non-authoritative provisioning inventory with same-scope opaque User edges;
they grant no role. Stable Group-to-role projection remains disabled until the
live Authentik profile and exact mapping are admitted. User disable/delete
revokes bound web sessions transactionally. SCIM resource IDs are opaque and
persistent; email addresses remain mutable indexed attributes. Legacy
email-keyed mailboxes move under SCIM ownership only through the reviewed,
digest-confirmed adoption path, which preserves mailbox identity and verifier.

The composition point is the database, not a provider-specific token parser.
The exact verified OIDC subject must equal one active SCIM User `externalId`,
and the verified email must equal that User's projected mailbox. The resulting
identity reference owns the session; a SCIM disable/delete revokes it in the
same transaction as deprovisioning.

## Extension-management composition

GOTTH Mail is the consumer and authority. It pins `gotth-extensions`, owns the
installed-extension registry and secret store, authenticates each out-of-
process service, issues the exact grant, and calls the extension-provided
control and seam services. A concrete extension repository supplies one
mechanism; it does not supply Mail policy or administrator presentation.

The browser communicates only with GOTTH Mail. Server-rendered administrator
routes use the same authorization, CSRF, service, transaction, and audit paths
as non-browser operations. Constrained extension metadata may describe fields
and named secret slots, but never executable UI. The webmail and administrator
may share visual tokens while their authority remains separate.

## Same-domain-only outbound composition

The per-domain outbound scope is a Mail-owned policy, not an identity-provider,
webmail, plugin, or MTA configuration preference. Authenticated mailbox,
admitted envelope-sender, system-sender, and expansion-source bindings form the
governing domain set; the canonical database stores each current policy and
revision; every submitter resolves recipients; and Postfix provides the final
enforcement boundary. Other hosted domains do not gain implicit trust. Inbound
mailbox delivery remains independent, while forwarding remains outbound.

This workstream is owner-prioritized immediately after the active live-identity
boundary and blocks alpha integration. Release evidence must show that SMTP,
webmail/API, expansion, automatic mail, queued retry/replay, restore, and final
transport cannot escape the policy and that policy uncertainty defers mail.

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
- Extension failure degrades only its mechanism. Disabling revokes its grant
  and blocks new routing before shutdown; uninstall and secret deletion are
  separate confirmed operations.

## Rollback

Each alpha/beta deployment retains the preceding application artifact,
configuration generation, database backup, and exact dependency lock. Schema
rollback is claimed only when rehearsed; otherwise rollback restores the paired
backup and prior artifact. Tags and failed candidates are never moved.
