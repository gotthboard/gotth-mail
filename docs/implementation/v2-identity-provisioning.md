# Implementation Spec — GOTTH Mail 1.0 Identity + Provisioning

Historical workflow ID: `v2.identity-provisioning`; it is not a product
version.

Source PRD: [PRD-v2-identity-provisioning.md](../prd/PRD-v2-identity-provisioning.md)
Source architecture: [architecture/v2-identity-provisioning.md](../architecture/v2-identity-provisioning.md)

## Goal

Add OIDC web/session login, Authentik role mapping, SCIM provisioning, app-password/mail-client token management, identity UI, and full permission simulator coverage.

OIDC, SCIM, and IMAP/SMTP credentials must stay separate.

## OIDC login

Flow:

```text
gotth_oidc.Begin -> persist_protected_attempt -> redirect_to_provider -> parse_callback -> atomically_consume_attempt -> gotth_oidc.Complete -> map_identity -> persist_session
```

OIDC login state is stored in `oidc_login_states`:

- `state_hash` 32-byte primary key
- `nonce_ciphertext` fixed-size protected envelope, not null
- `pkce_verifier_ciphertext` fixed-size protected envelope, not null
- `context_ciphertext` bounded protected attempt context, not null
- `browser_binding_hash` 32-byte digest, not null
- `redirect_after_login`
- `created_at`
- `expires_at`
- `used_at`

The browser receives the raw state; only its SHA-256 lookup digest is stored.
Raw state, nonce, PKCE verifier, authorization code, and tokens are never
written to the database or logs. The callback atomically marks the matching
attempt used before calling `oidc.Client.Complete`. This prevents concurrent
redemption. Network or validation failure after consumption does not restore
the attempt; the user starts a new login.

An upgrade migration invalidates all pre-adoption in-flight attempts, removes
the plaintext state/nonce columns, and installs fixed-length protected columns.
Application sessions remain separate and are not invalidated by that migration.
Because the protected-attempt schema is intentionally incompatible with the
legacy raw-state schema, operators must apply this migration during a
coordinated restart. Mixed old/new GOTTH Mail processes are not supported
during this one-time upgrade.

Validation requirements:

- state exists, unexpired, unused, and bound to initiating browser/session
- nonce matches ID token claim
- redirect URI exactly matches configured public URL callback
- issuer equals configured/discovered issuer
- signature verifies against JWKS
- subject exists and is stable
- audience contains configured client ID
- authorized party (`azp`) matches client ID when present
- expiry, issued-at, and not-before are valid with bounded clock skew
- no unsigned-claim fallback
- exact `gotth-oidc` protected-attempt and S256 PKCE behavior

Failures return safe errors and log no tokens.

Runtime configuration uses `GOTTH_MAIL_DATABASE_URL_FILE` and
`GOTTH_MAIL_AUTHENTIK_CLIENT_SECRET_FILE` for container secrets where
available; their direct environment counterparts are mutually exclusive
fallbacks. OIDC configuration without a migrated PostgreSQL store fails
startup. Provider discovery occurs only after database migration and durable
identity-state loading succeed.

## Session model

Session fields:

- `id`
- `identity_ref_id`
- `created_at`
- `expires_at`
- `last_seen_at`
- `csrf_secret_hash`
- `auth_method` = `oidc|local|break_glass`

Session cookies:

- HttpOnly
- Secure in non-dev
- SameSite=Lax or stricter
- rotation on login

OIDC sessions grant web/API session access only. They never authenticate IMAP/SMTP.

`gotth-oidc` returns issuer, subject, display name, verified email, and safe
picture identity facts. It does not return authorization-shaped group claims.
GOTTH Mail maps roles from its separately verified durable mapping path.

The configured PostgreSQL store implements identity-session admission as one
transaction:

1. select active SCIM User projections whose `externalId` equals the verified
   OIDC subject;
2. require exactly one candidate and require its mailbox address to equal the
   verified OIDC email after case folding;
3. insert the exact `(provider, issuer, subject)` identity reference, or verify
   that the existing reference still names the same mailbox UUID;
4. insert the foreign-keyed application session and redacted login-success
   audit event; and
5. commit all three records together.

The migration removes legacy Authentik identity rows and all pre-binding
sessions because their issuer/mailbox provenance cannot be reconstructed.
It preserves local identity rows, normalizes the historical scoped role name,
adds exact identity uniqueness, prevents two Authentik subjects from owning the
same mailbox, and makes `sessions.identity_ref_id` a UUID foreign key.

## Authentik role mapping

Role mapping source is the required Authentik profile. Stored mapping includes:

- `authentik_group_id_or_name`
- target role: `global_admin`, `domain_manager`, `scoped_domain_access`
- optional domain selector
- verification status and last checked timestamp

Doctor checks:

- required groups exist
- mapped roles can be resolved
- domain-scoped mappings match known domains or documented selectors
- mail delivery/daemon lookups still pass when Authentik is unavailable

No local manual edit should be required to assign global admin/domain manager/scoped domain access through Authentik.

## Permission simulator

API:

```text
POST /api/v1/authz/explain
```

Request:

```json
{
  "actor": {"type": "oidc_subject", "id": "..."},
  "action": "mailbox.create",
  "resource": {"type": "domain", "id": "..."}
}
```

Response:

```json
{
  "decision": "allow|deny",
  "matched_rules": ["domain_manager:create_mailbox"],
  "missing_requirements": [],
  "correlation_id": "..."
}
```

Must cover local admin, API token, OIDC subject, SCIM client, system actor, break-glass actor, global admin, domain manager, scoped domain access, and denied results.

## SCIM API

The HTTP surface is implemented by `gotth-scim.Server`, not the handwritten
legacy router. GOTTH Mail supplies:

- bearer authentication middleware and opaque provisioning scopes;
- a PostgreSQL implementation of `scim.Store`/`scim.Transaction`;
- `scim.PasswordStore` only when password projection is atomic with resource
  mutation and audit;
- mailbox, verifier, audit, role, and session-invalidation projection;
- product-specific disable semantics and recovery evidence.

The adapter must pass `scim.CheckStore` and product tests. `scim.MemoryStore`
is restricted to library/HTTP fixtures and is never production durability.

Base path:

```text
/scim/v2
```

Endpoints:

```text
GET    /ServiceProviderConfig
GET    /ResourceTypes
GET    /Schemas
GET    /Users
POST   /Users
GET    /Users/{id}
PUT    /Users/{id}
PATCH  /Users/{id}
DELETE /Users/{id}
GET    /Groups
POST   /Groups
GET    /Groups/{id}
PUT    /Groups/{id}
PATCH  /Groups/{id}
DELETE /Groups/{id}
```

Groups use `gotth-scim` protocol behavior. For GOTTH Mail 1.0 every member must
have `type=User` (or omit type so the library canonicalizes it) and `value`
must name a live opaque User ID in the same storage scope. Nested Groups,
missing users, cross-scope users, duplicate members, and deleting a referenced
User fail closed. `scim_group_members(scope, group_id, user_id)` is replaced
atomically with Group canonical data and audit. Group deletion cascades its
edges; User deletion is restricted until membership is removed.

This enables provisioning inventory, not authorization. No Group name or
membership becomes a product role until the admitted Authentik profile maps an
exact stable Group resource to a durable `role_bindings` policy. No ID-token
group claim bypasses this mapping.

SCIM requests authenticate as a `scim_client` actor using a verifier-backed bearer/API token. Every create/update/patch/deprovision request runs through core authorization and domain policy before canonical mailbox state is admitted.

User mapping:

- `userName` -> mailbox email
- `displayName` or `name.formatted` -> display name
- `active` -> enabled flag
- `password` -> mailbox password when supplied; stored as an Authentik-compatible Django encoded password-hash string

Validation rejects:

- malformed JSON
- non-object payloads
- invalid scalar identity fields
- unsupported patch operations
- unknown paths
- bad password values
- mailbox/domain outside allowed policy

Supported PATCH matrix:

- `add` or `replace` `/active` with boolean value
- `add` or `replace` `/displayName` with string value
- `add` or `replace` `/name/formatted` with string value
- `add` or `replace` `/password` with valid string password
- `remove` `/displayName` or `/name/formatted`

All other operations or paths fail explicitly. Empty Operations arrays fail explicitly.

SCIM DELETE disables the mailbox by default and does not delete mail data.

SCIM disable and delete also set `revoked_at` on every active session reached
through that mailbox's `identity_refs` in the same transaction. A bound User's
`externalId` is immutable; changing it requires an explicit adoption workflow,
not an ordinary SCIM replace.

Authentik is the first expected SCIM client. Authentik calls GOTTH Mail SCIM; GOTTH Mail validates, authorizes, writes canonical mailbox state, and audits mutations. Authentik never writes directly to DB or daemon config.

Runtime enablement uses `GOTTH_MAIL_SCIM_EXTERNAL_URL`, which must identify the
external `/scim/v2` base. SCIM cannot start without the migrated PostgreSQL
identity store. Every request, including discovery, requires a verifier-backed
`scim_client` bearer. The stable token actor ID, not its rotatable secret,
derives the opaque storage scope.

Migration `0004_scim_resources` stores resources, ordered search indexes,
immutable index contracts, permanent tombstones, and the mailbox-to-resource
binding. Nanosecond timestamps are stored as integers because the imported
store contract requires exact round trips. A User create/replace/patch/delete,
optional `PasswordTransaction.SetPassword`, mailbox projection, and success
audit row execute in one serializable transaction with no application retry of
the callback. SQL uniqueness failures become SCIM conflicts. Password bytes
are cleared by the protocol library after the consumer hashes them; only the
Django PBKDF2-SHA256 verifier and a non-secret credential revision persist.

The process mutex deliberately orders commits with the current process-local
daemon/passdb projection. PostgreSQL constraints remain authoritative across
processes, but multiple control-plane writers are not admitted because their
memory views would diverge until restart. Startup reloads SQL mailboxes and
rebuilds the daemon view. The deployment must run one control-plane writer
until explicit cache propagation replaces this constraint.

Legacy email-keyed mailbox rows are not automatically converted. The operator
uses:

```text
gotth-mailctl identity adopt preview --config <file> --mailbox <address> \
  --subject <authentik-subject> --scope <scim-scope> --manager <manager>

gotth-mailctl identity adopt apply --config <file> --mailbox <address> \
  --subject <authentik-subject> --scope <scim-scope> --manager <manager> \
  --confirm <preview-digest>
```

Preview selects exactly one mailbox by normalized address and requires
`scim_resource_id IS NULL`. Its canonical JSON contains the mailbox UUID,
address, display name, enabled state, creation timestamp, update timestamp,
subject, scope, and manager; it never contains the verifier. `plan_id` is the
lowercase SHA-256 digest of that canonical JSON.

Apply runs preview again and constant-time compares the supplied digest. It
constructs a standard User document and calls `gotth-scim.Reconciler` with one
desired resource and `DeleteMissing=false`. `gotth-scim` validates the
document, owns opaque resource-ID generation, and applies its manager/external
ID reconciliation rules. A transaction-local adoption claim contains the
expected mailbox UUID and update timestamp. The SQL adapter locks that row,
requires the same unowned address and version, preserves its UUID, verifier,
creation time, and enabled state, sets only the SCIM ownership and admitted
display state, and writes `scim.user.create` audit before commit.

No issuer is accepted by this command and no `identity_refs`, sessions, or
role bindings are created. The first verified OIDC callback remains the sole
issuer/subject/session admission path. Existing ownership, stale plans,
subject conflicts, tombstones, malformed input, missing/disabled domains, and
audit failure all reject atomically. A Group may inventory an adopted User's
opaque ID before verified subject binding exists, but it grants no product
authorization; only the separately admitted stable Group-to-role projection
may create authority.

## SCIM error contract

Use SCIM error shape:

```json
{
  "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
  "status": "400",
  "scimType": "invalidValue",
  "detail": "safe message"
}
```

Unsupported groups or operations must fail explicitly. No fake 200/no-op behavior.

## Password hashing compatibility

Mailbox-password and app-password/mail-client verifier storage uses Django
encoded password-hash syntax with the current GOTTH Mail 1.0 compatibility
profile fixed to `pbkdf2_sha256`, matching the checked Authentik/Django default
deployment.

Requirements:

- new mailbox passwords are encoded as `pbkdf2_sha256$iterations$salt$digest`
- stored verifier strings include the Django algorithm identifier and parameters
- imported hashes are accepted only when they are valid `pbkdf2_sha256` verifier strings
- `argon2`, `bcrypt_sha256`, `scrypt`, `pbkdf2_sha1`, and other Django-recognized algorithms are rejected until local verification support exists
- Dovecot passdb verifies submitted secrets against the same stored verifier string
- plaintext password import/export is rejected
- unknown, deprecated, or policy-disabled hash algorithms are rejected unless a documented migration exception is recorded
- Authentik outage must not affect Dovecot passdb verification of already-stored verifiers

This contract intentionally matches the active Authentik default hash format without pretending generic Django hasher compatibility exists. It does not make Authentik a runtime dependency for IMAP/SMTP login.

## App passwords / mail-client tokens

API:

```text
GET    /api/v1/mailboxes/{id}/app-passwords
POST   /api/v1/mailboxes/{id}/app-passwords
DELETE /api/v1/mailboxes/{id}/app-passwords/{token_id}
```

Create response exposes plaintext secret once:

```json
{
  "id": "uuid",
  "label": "phone",
  "secret_once": "generated-secret",
  "created_at": "..."
}
```

Storage:

- store Authentik-compatible Django encoded verifier/hash strings where password sync or Dovecot verification is intended
- store the opaque API credential ID in `tokens.public_id` and the human label
  in `tokens.label`; migration `0005_app_password_contract` backfills legacy
  app-password public IDs from the old overloaded label field
- never log plaintext secret
- never return secret after creation
- revocation sets `revoked_at`
- Dovecot passdb validates against the same stored verifier string
- configured runtime passdb success requires durable audit admission; an audit
  failure returns a temporary failure instead of accepting unaudited use
- enforce a maximum of eight active app passwords per mailbox while holding
  the mailbox row lock; a ninth concurrent or sequential create fails
- reject startup when persisted active app-password state violates that bound

Migration preflight must reject, rather than truncate, a legacy app-password
label outside the new 1–128 byte contract. Operators must rename such labels
before retrying the migration; the verifier and revocation state are never
rewritten merely to make the schema apply.

Configured PostgreSQL create/revoke uses a database transaction that contains
the token mutation and normalized success audit insert. The process-local
Dovecot projection changes only after commit. Failure and denied attempts are
audited through the configured writer, but never called success.

Audit events:

- create
- revoke
- successful use metadata
- failed use metadata without secret

## Identity UI

GOTTH pages:

- OIDC/Auth status
- Authentik role/group mapping
- read-only SCIM capability/status linked to `/scim/v2`; never a second
  handwritten provisioning path
- app-password list/create/revoke only after the `gotth-oidc` application
  session maps through durable identity/role state to the target mailbox
- permission simulator

All mutations use service/auth/audit paths. Before that session binding is
admitted, the browser UI renders an explicit unavailable status and no
mutation forms. The scoped bearer API remains the only admitted management
surface; expecting an HTML form to supply a bearer header is not a design.

After binding, the app-password API accepts either its existing scoped bearer
token or a live `gotth_mail_session` cookie resolved through the SQL identity
store. Session actors receive only their bound mailbox. POST/DELETE requests
must also supply the separate CSRF cookie value in `X-CSRF-Token`; the server
compares its digest to the session record. Session and CSRF secrets never enter
JSON responses, logs, audit data, or mail verifier storage.

## Plugin identity boundary

Plugin service identity authenticates plugin admission only. It cannot grant roles, create users, or bypass core validation.

## Verification

Required tests:

- OIDC state, nonce, redirect URI, issuer, signature, subject, audience, azp, exp, iat, nbf validation
- invalid state/nonce/token negative tests
- raw state/nonce/PKCE/token absence from persistence and logs
- migration invalidates legacy in-flight attempts without invalidating sessions
- concurrent callback replay permits exactly one attempt consumption
- process restart between login start and callback preserves the protected
  attempt; restart after callback preserves the application session
- no unsigned-claim fallback test
- no token disclosure in failure logs
- Authentik role mapping doctor/tests for global admin/domain manager/scoped access
- mail delivery/daemon lookup checks with Authentik unavailable
- permission simulator coverage for all actor classes and denied results
- OIDC login state is single-use and marked used atomically with callback acceptance
- SCIM client authentication/authorization tests
- SCIM success paths for list/create/read/replace/patch/disable
- SCIM failure paths for malformed JSON, non-object payload, scalar identity fields, unsupported operations, unknown paths, empty Operations arrays, bad passwords
- Authentik-compatible SCIM provisioning path without DB/config bypass
- `scim.CheckStore` against the PostgreSQL adapter plus concurrent uniqueness,
  opaque-ID persistence, tombstone non-reassignment, restart, backup, and
  restore tests
- password-hash compatibility tests for the current GOTTH Mail 1.0
  `pbkdf2_sha256` Authentik/Django default profile plus rejection tests for
  unsupported Django hashers
- app-password create/revoke/list/Dovecot auth with `pbkdf2_sha256` Django encoded verifier/hash storage where applicable
- stable public ID and human label persistence across restart
- atomic SQL create/revoke plus success audit, including rollback injection
- eight-active-credential boundary under concurrent creation and startup
- runtime UI uses the configured identity service and exposes no fake SCIM or
  unauthenticatable app-password mutation path
- every identity/provisioning mutation audited
- exact subject/externalId/email binding and ambiguous/missing/disabled
  candidate rejection
- session, identity reference, and login-success audit atomicity
- session expiry and SCIM disable/delete revocation across restart
- same-mailbox-only session app-password access and cross-mailbox denial
- CSRF missing/mismatch rejection and session/CSRF secret non-disclosure
- `git diff --check`
- `go test ./...`
