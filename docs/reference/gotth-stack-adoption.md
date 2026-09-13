# GOTTH component adoption contract

This record defines which reusable GOTTH components GOTTH Mail uses, where the
product boundary remains consumer-owned, and why a component is not imported
when it does not fit. Repository branding is not an architectural argument.

The revisions below were inspected on 2026-09-13. Every imported module must
remain pinned to an exact reviewed revision until an immutable compatible tag
is admitted.

| Component | Inspected revision | GOTTH Mail decision |
| --- | --- | --- |
| `gotth-oidc` | `1ae119e52f8efc3392fcc9fa716b1b27c9ffce6c` | Adopted on the 1.0-alpha development line for discovery, Authorization Code, S256 PKCE, protected attempt material, callback parsing, code exchange, and ID-token validation. GOTTH Mail owns durable one-time attempt consumption, browser binding, identity records, application sessions, cookies, and authorization. |
| `gotth-scim` | `255629e27f7df301d263a116fb37fd315ff54693` | Adopted on the 1.0-alpha development line for SCIM parsing, RFC behavior, opaque IDs, transactions, ETags, PATCH/search/Bulk, tombstones, reconciliation, and write-only password delegation. GOTTH Mail owns bearer authentication, provisioning scopes, PostgreSQL storage, mailbox/password/audit projection, session invalidation, and product policy. |
| `gotth-authentik` | `0587d298d317247cd5c86a4beff23c705da395e0` | Intended for the live Authentik desired-state/profile proof after its license is selected and its consumer contract is admitted. It is not imported or copied while unlicensed. |
| `gotth-pg-migrate` | `6a513260994ab01ad525f7ab8909f8fa65cebe41` | Candidate for a separately reviewed migration-engine cutover. It is not mixed into the identity slices: it is currently unlicensed and its six-digit immutable-file ledger is incompatible with GOTTH Mail's existing table-name baseline ledger. |
| `gotth-release` | `2d918925dfd8550cb0a58f4569561d624addd5d2` | Intended for deterministic 1.0 alpha/beta/stable artifacts after licensing and a product-specific archive manifest are admitted. It does not belong in runtime identity code. |
| `gotth-infrastructure` | `785ca581417c8cbaea4594d4e2b0be01828a94be` | Candidate for the control-plane container's desired-state and inspect proof after licensing. Its one-container contract does not model the complete Postfix/Dovecot/Rspamd/Authenik stack, so product deployment orchestration remains GOTTH Mail-owned. |
| `gotth-jobs` | `1c7b229f24e61a65c477408282aed74602dd3cab` | Available for later durable asynchronous work with at-least-once semantics. It is deliberately excluded from login and canonical SCIM mutation because those paths require synchronous, fail-closed acceptance rather than eventual projection. |
| reserved `gotth-*` repositories | current public `main` | Do not import placeholders or unrelated product components. A component becomes eligible only when it has a real API, an applicable mechanism, an acceptable license, exact version provenance, and consumer evidence. |

## Immediate identity sequence

1. Replace duplicate in-tree OIDC protocol code with `gotth-oidc` while
   preserving GOTTH Mail's existing login/callback URLs and session-cookie
   userspace.
2. Persist only `gotth-oidc.ProtectedAttempt` material plus consumer-owned
   browser-binding, return-path, expiry, and consumption metadata. Raw state,
   nonce, and PKCE verifier values must never be stored.
3. The handwritten SCIM HTTP surface is replaced by `gotth-scim`, backed by a
   transaction-bearing PostgreSQL adapter and atomic mailbox/password/audit
   projection. The adapter passes `scim.CheckStore` plus focused product
   restart and concurrency tests; backup, restore, and live Authentik evidence
   still gate workstream completion.
4. Migrate email-address SCIM identifiers to opaque persistent IDs. Old
   identifiers may be resolved only through an explicit bounded migration
   record; they must never be regenerated from a mutable address.
5. Use SCIM Groups for role membership only after the exact binding between an
   Authentik OIDC subject and a SCIM User `externalId` is specified and proven.
   OIDC authorization-shaped claims are not trusted merely because a provider
   placed them in an ID token.
6. Use `gotth-authentik` for the real provider/application/enrollment profile
   only after its legal and release gates are satisfied, then run live login,
   provision, role, disable, deprovision, restart, backup, and restore proofs.

## OIDC runtime configuration

OIDC is enabled only when all three non-secret bindings are present:

- `GOTTH_MAIL_AUTHENTIK_ISSUER`
- `GOTTH_MAIL_AUTHENTIK_CLIENT_ID`
- `GOTTH_MAIL_AUTHENTIK_REDIRECT_URI`

The client secret may be supplied by exactly one of
`GOTTH_MAIL_AUTHENTIK_CLIENT_SECRET` or
`GOTTH_MAIL_AUTHENTIK_CLIENT_SECRET_FILE`. The file form is preferred for a
container secret. Public clients may omit both only when the provider metadata
admits `none` client authentication.

OIDC additionally requires exactly one durable database source:
`GOTTH_MAIL_DATABASE_URL` or `GOTTH_MAIL_DATABASE_URL_FILE`. Startup opens and
pings PostgreSQL, applies the checked migration ledger, loads the durable
identity service, and only then discovers the OIDC provider. A partial OIDC
binding, two competing secret sources, database failure, migration failure, or
provider-discovery failure stops startup. With no OIDC binding the OIDC routes
return unavailable; they never pretend an in-memory production login is
durable.

Migration `0003_oidc_protected_attempts` deletes only legacy in-flight login
attempts, preserves application sessions, removes plaintext state/nonce
columns, and installs fixed-size protected fields. Operators should expect
users who began login before the migration to restart that login once.

## SCIM runtime configuration

SCIM is enabled only when `GOTTH_MAIL_SCIM_EXTERNAL_URL` is present. The value
is the externally reachable base URL, including `/scim/v2`. Enabling SCIM also
requires the same migrated PostgreSQL source used by identity state:
`GOTTH_MAIL_DATABASE_URL` or `GOTTH_MAIL_DATABASE_URL_FILE`. Startup fails if
SCIM is requested without durable storage or a loaded identity service.

The runtime authenticates every SCIM request, including discovery, with an
active verifier-backed token of kind `scim_client`. Each stable token actor ID
maps to an opaque SHA-256-derived storage scope; rotating a token secret while
preserving its actor ID preserves the tenant scope. Changing the actor ID is a
new scope and therefore does not expose or silently adopt the old resources.

Migration `0004_scim_resources` adds opaque resource IDs to mailboxes and
creates canonical resource, ordered-index, index-contract, and permanent
tombstone tables. Each accepted User mutation, optional write-only password
projection, mailbox update, and success audit record commits in one
serializable PostgreSQL transaction. Password bytes are passed directly to the
consumer-owned hasher, reduced to a Django PBKDF2-SHA256 verifier and opaque
credential revision, and are never stored in the SCIM document or audit body.

After commit, the single running control-plane process updates its in-memory
daemon/passdb view without I/O. PostgreSQL remains authoritative, and startup
rebuilds that view. A multi-writer/multi-process control plane is not admitted
yet because one process cannot update another process's cache. That limitation
must be removed or made operationally impossible before horizontal runtime
scaling.

SCIM Groups return explicit `501 Not Implemented` until group members are bound
to opaque SCIM User IDs and each User `externalId` is proven to be the matching
Authentik OIDC subject. The same missing binding prevents honest SCIM-driven
web-session invalidation. No ID-token group claim is trusted as a shortcut.

Legacy email-keyed mailbox rows are not guessed into SCIM ownership. Adoption
requires an operator-reviewed mapping that records the existing mailbox, new
opaque resource ID, authoritative Authentik subject, and rollback evidence.
Fresh SCIM-created resources and renames never use an email address as their ID.

## Admission rule

Compatibility tests prove only that a library can be called. Runtime adoption
is complete only when duplicate production mechanics are removed, consumer
adapters are durable, failure paths are covered, live integration is proven,
and the exact dependency revision is recorded. No component tag, GOTTH Mail
alpha, or stable claim follows from a package import alone.
