# Architecture — GOTTH Mail 1.0 Identity + Provisioning

Historical workflow ID: `v2.identity-provisioning`; it is not a product
version.

Source PRD: [PRD-v2-identity-provisioning.md](../prd/PRD-v2-identity-provisioning.md)

## Goal

This workstream adds identity and provisioning on top of the working mail core.
OIDC is for web/session login. SCIM is for provisioning. App passwords and
mail-client tokens are for IMAP/SMTP clients. These must remain separate.

## OIDC architecture

OIDC uses `github.com/gotthboard/gotth-oidc/pkg/oidc` and its Authorization
Code flow. The library owns discovery, endpoint policy, S256 PKCE, protected
attempt material, callback parsing, token exchange, and identity-token
validation. GOTTH Mail does not retain a second protocol implementation.

GOTTH Mail owns a narrow consumer adapter:

- atomically persist and consume `oidc.ProtectedAttempt` by its state hash;
- hash the independent browser-binding cookie before storage;
- store the local return path, creation, expiry, and consumption timestamps;
- create and persist the application session only after verified completion;
- consume an attempt before external code exchange so concurrent/replayed
  callbacks cannot both redeem it; a failed exchange leaves the attempt spent;
- preserve the existing login/callback routes and secure cookie behavior.

Raw state, nonce, PKCE verifier, authorization code, ID token, access token,
and refresh token are never stored by the default GOTTH Mail login path.

Required protections:

- provider discovery
- JWKS handling
- callback state generation and validation
- nonce generation and validation
- exact redirect URI validation against configured public URLs
- ID token validation:
  - issuer
  - signature
  - subject
  - audience
  - authorized party (`azp`) when present
  - expiry
  - issued-at
  - not-before
- no unsigned-claim fallback
- failure logging without token disclosure

`gotth-oidc` returns provider-neutral identity facts and deliberately excludes
authorization-shaped claims. GOTTH Mail therefore does not grant a role from
an ID-token `groups` claim. Role membership comes from the separately verified
product mapping/provisioning path.

After token verification, the SQL consumer resolves exactly one active
`gotth-scim` User projection. The User `externalId` must equal the verified
OIDC subject, and the projected mailbox address must equal the verified email.
That check binds the exact issuer/subject pair to the mailbox UUID in
`identity_refs`; session creation and its redacted success audit commit in the
same transaction. Missing, duplicate, disabled, or email-mismatched candidates
produce no identity row and no session.

`sessions.identity_ref_id` is a real UUID foreign key. The adoption migration
invalidates pre-binding application sessions and unproven Authentik identity
rows instead of guessing provenance from the old `issuer|subject` text. Local
identity rows and their role bindings remain intact. A live session resolves
through the identity and active mailbox on every privileged browser request,
so SCIM deprovisioning cannot leave a detached cookie authoritative.

OIDC creates web sessions only. It does not authenticate IMAP/SMTP clients.

## Authentik role mapping architecture

Authentik is required and adjacent. It is not embedded.

The pinned `gotth-authentik` renderer is a build-time desired-state tool, not
a runtime dependency and not a remote-control client. GOTTH Mail owns a small
JSON manifest and the byte-for-byte rendered blueprint. The manifest fixes the
application slug `gotth-mail`, provider `gotth-mail-oidc`, client ID
`gotth-mail`, access group `gotth-mail-users`, and strict callback. The
blueprint contains no client secret; Authentik generates and retains that
secret, and the deployment supplies it to GOTTH Mail from a root-readable
file.

Migration is additive first. The new provider/application/profile is imported
alongside the historical `gophermailforge` objects and the old provider stays
recoverable while the new path is tested. The initial loopback callback is
only a local authorization-code smoke boundary. A deployed public instance
must replace it with one exact HTTPS callback before beta. The old objects may
be retired only after browser, SCIM, deprovision, restart, backup, restore, and
rollback evidence exists.

`gotth-mail-users` is an application admission gate only. It does not project
product roles, is not read from the ID token, and cannot bypass the durable
SCIM-to-role mapping. The current `gotth-authentik` contract does not create an
Authentik SCIM provider; that remains a separate GOTTH Mail-owned live profile
and evidence gate.

Required mappings:

- global admins
- domain managers
- scoped domain access

Mappings are represented in core state and verified by tests/doctor. No local manual edits should be required to assign these roles.

Authentik outage may break new SSO/provisioning actions but not mail delivery or daemon lookup paths.

## Permission simulator architecture

The permission simulator explains actor/action/resource decisions for:

- local admin
- API token
- OIDC subject
- SCIM client
- system actor
- break-glass actor

It explains:

- global admin access
- domain manager access
- scoped domain access
- denied results

UI/API/CLI use the same explanation model.

## SCIM architecture

SCIM uses `github.com/gotthboard/gotth-scim/pkg/scim`. The library owns the
RFC protocol surface, bounded parsing, schema validation, opaque IDs, ETags,
PATCH/search/Bulk behavior, tombstones, reconciliation, and the transaction
contract. GOTTH Mail supplies bearer authentication, a provisioning-scope
resolver, a PostgreSQL `scim.Store`, atomic password projection, mailbox state,
audit, role/session policy, and operational recovery.

SCIM exposes:

- ServiceProviderConfig
- ResourceTypes
- Schemas
- Users list/create/read/replace/patch/deprovision
- Groups as non-authoritative provisioning inventory after same-scope opaque
  User membership is enforced; role authority remains disabled until the
  Authentik profile and exact product mapping are separately admitted

Mapping:

- `userName` -> mailbox email
- `displayName` / `name.formatted` -> displayed name
- `active` -> enabled flag
- `password` -> mailbox password when supplied, stored using the current GOTTH
  Mail 1.0 Authentik/Django `pbkdf2_sha256` encoded password-hash format

Validation rejects:

- malformed JSON
- non-object payloads
- invalid scalar identity fields
- unsupported patch operations
- unknown paths
- bad password values

SCIM DELETE disables mailbox by default. It does not delete mail data.

The product adapter preserves `gotth-scim` tombstones and opaque resource IDs.
Deleting or renaming a mailbox never frees or regenerates the SCIM identity.
The adapter must pass `scim.CheckStore`; that library check is necessary but
does not replace product restart, concurrency, migration, backup, restore, and
mailbox/audit projection evidence.

Group resource parsing, schema behavior, ETags, PATCH, discovery, and opaque
IDs remain `gotth-scim` responsibilities. GOTTH Mail projects normalized
Group-to-User edges into `scim_group_members` in the same transaction as the
resource and audit. Every member must be an existing User in the same scope;
nested Groups are rejected. Foreign keys cascade Group deletion and restrict
User deletion while referenced. This table is provisioning state, not an
authorization cache. Until the live Authentik desired-state profile maps exact
group IDs to durable role bindings, Group membership grants nothing.

Canonical SCIM resources, ordered indexes, immutable index contracts, and
permanent tombstones live in PostgreSQL. A stable authenticated `scim_client`
actor ID derives an opaque storage scope; token-secret rotation preserves scope
only when that actor ID is preserved. User resource mutation, write-only
password hashing, mailbox projection, and success audit admission share one
serializable transaction. A failure in any member rolls the transaction back.

The committed SQL state is authoritative. The current single control-plane
process projects accepted mailboxes into its in-memory daemon/passdb view only
after commit and rebuilds the view on startup. Horizontal multi-writer runtime
operation is not admitted until cache propagation is explicit. Legacy
email-keyed mailbox rows likewise require an operator-reviewed opaque-ID and
Authentik-subject adoption record; provenance cannot be inferred from an
address.

Legacy adoption is a narrow composition of existing mechanisms. A preview
reads one unowned mailbox and returns a redacted plan plus SHA-256 confirmation
digest. Apply reconstructs the plan from current SQL state, requires the exact
digest, and invokes `gotth-scim.Reconciler` with one User desired resource.
The library validates the SCIM document and generates the opaque resource ID.
The GOTTH Mail SQL adapter consumes a transaction-local adoption claim, locks
the exact mailbox UUID/version, attaches the resource ID, preserves its
verifier and creation time, and writes the normal SCIM audit before commit.
The claim is valid for one exact mailbox and cannot make ordinary SCIM creates
adopt address collisions.

This operation records provisioning ownership only. It deliberately does not
pre-create `identity_refs`, sessions, or roles. A later verified
`gotth-oidc` callback still has to match the adopted User `externalId` and
mailbox email before the issuer/subject binding exists. Rollback is the normal
SCIM manager-owned delete/disable path plus database restore evidence; an
opaque ID or tombstone is never recycled.

The outbound Authentik provider and inbound GOTTH Mail endpoint share one
bearer, but they do not share plaintext storage. An operator first creates a
high-entropy bearer in an owner-only regular file. `gotth-mailctl identity
scim-token preview` validates the file and reads the current token row without
printing a fingerprint or secret. Its confirmation digest binds the stable
actor ID, requested secret digest, current verifier digest, revocation state,
and intended create/rotate/reactivate/no-op transition.

`apply` opens a serializable PostgreSQL transaction, locks the exact token row,
reconstructs the plan, and compares the confirmation digest in constant time.
For a mutation it writes a fresh Django PBKDF2-SHA256 verifier and a redacted
audit event before committing. The audit names only the actor ID and operation.
The raw bearer remains solely in the operator-owned file so it can be installed
into Authentik; it is never persisted or echoed by GOTTH Mail. A same-secret
retry performs no write. The actor ID does not change during rotation, so
`provisioningScope(actor.ID)` continues to select the same opaque SCIM scope.

Secret-file validation is part of the trust boundary: the path must resolve to
a regular non-symlink file with no group/world permission bits, and the value
must be bounded, non-whitespace, printable bearer-safe data with at least 32
bytes. Command-line and environment secret values are not accepted. This is a
Linux/Docker operator mechanism, not an end-user credential workflow.

SCIM disable/delete revokes sessions through the mailbox UUID inside the same
transaction as the mailbox transition and SCIM audit. Changing an
`externalId` after an OIDC identity has been bound is rejected; silently moving
an authenticated subject to another mailbox is not a rename.

## GOTTH component allocation

The authoritative allocation, exact inspected revisions, legal gates, and
non-adoption reasons live in
[the GOTTH component adoption contract](../reference/gotth-stack-adoption.md).
`gotth-authentik` is MIT-licensed and admitted at the exact revision in the
adoption contract for secret-free OIDC/enrollment desired state only. Its
remote application, rollback, runtime secret handling, access membership, and
SCIM provider remain consumer/operator responsibilities. `gotth-pg-migrate`,
`gotth-release`, and `gotth-infrastructure` are
also MIT-licensed but still require separate compatibility work. `gotth-jobs`
is not placed in the synchronous login or canonical provisioning transaction.

Authentik is the expected first SCIM client. Authentik calls the GOTTH Mail SCIM endpoint; GOTTH Mail validates requests, enforces domain policy, writes canonical mailbox state, and audits provisioning mutations. Authentik does not write directly to the database or daemon config.

## App-password architecture

App passwords/mail-client tokens:

- are created/revoked/listed through core services
- integrate with Dovecot auth
- have a stable opaque public ID distinct from the operator-supplied label
- are stored as the current GOTTH Mail 1.0 Authentik/Django `pbkdf2_sha256`
  encoded password-hash/verifier strings where password sync or Dovecot
  verification is intended; never plaintext
- expose the secret value only at creation
- retain the existing opaque random secret format; secrets do not embed
  database identifiers
- permit at most eight active credentials per mailbox, bounding a failed
  Dovecot lookup to one mailbox-password verifier plus eight app-password
  verifiers instead of an attacker-controlled unbounded PBKDF2 scan
- emit audit events for create/revoke/use metadata
- defer an otherwise successful passdb authentication when its configured
  durable audit writer fails; accepted credential use is never silently lost

On PostgreSQL, credential create/revoke and the matching success audit record
share one transaction. The mailbox row is locked while the active-count gate
and mutation are admitted, so concurrent creators cannot exceed the limit.
The committed SQL row is authoritative; the single control-plane process
updates its Dovecot verifier projection only after commit and rebuilds it on
startup. Mailbox and app-verifier projection writes share the daemon state's
read/write lock with passdb snapshots. A passdb request copies only the target
mailbox's bounded verifier slice; it does not clone the entire mailbox/token
map per authentication or race a concurrent create/revoke projection.

## Identity UI

GOTTH UI surfaces:

- OIDC/Auth status
- Authentik role/group mapping screens
- a read-only SCIM capability/status page that points at the real
  `gotth-scim` endpoint
- app-password self-service only after a verified OIDC session resolves
  through durable `identity_refs` and role bindings to the target mailbox
- permission simulator UI

UI mutations go through the same service/auth/audit layers as the API. The
current bearer-token API cannot be smuggled into HTML forms: browsers do not
invent an `Authorization` header for ordinary form posts. Until the durable
OIDC subject-to-mailbox/role binding is admitted, those mutation forms remain
absent and the UI states the blocker. The old in-process SCIM test shortcut is
not an acceptable substitute for the real `gotth-scim` route.

Once the binding is present, app-password API requests may authenticate with
the HttpOnly application-session cookie. They receive only same-mailbox
authority. Mutating requests additionally prove a separate CSRF secret bound
to the stored session hash; bearer automation remains supported and does not
use the browser CSRF mechanism.

## Plugin identity boundary

Plugins cannot grant identity authority.

Plugin service identity proves the plugin is admitted; it does not grant user/admin permissions. Role mapping remains core.

## Verification gates

- OIDC login validates state, nonce, exact redirect URI, and ID token claims
- invalid callback state/nonce rejected
- malformed/unverifiable tokens rejected
- Authentik mappings assign global admin/domain manager/scoped access
- permission simulator explains identity-backed decisions
- SCIM success and failure paths tested
- Authentik-compatible SCIM provisioning path verified without bypassing GOTTH Mail validation/state admission
- app passwords work for Dovecot auth using the same Authentik-compatible Django encoded hash/verifier contract where applicable
- every identity/provisioning mutation audited
