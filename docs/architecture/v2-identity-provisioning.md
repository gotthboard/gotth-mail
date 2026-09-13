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

OIDC creates web sessions only. It does not authenticate IMAP/SMTP clients.

## Authentik role mapping architecture

Authentik is required and adjacent. It is not embedded.

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
- Groups only after the OIDC-subject to SCIM-`externalId` binding and product
  role-mapping semantics are admitted; until then they fail explicitly

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

## GOTTH component allocation

The authoritative allocation, exact inspected revisions, legal gates, and
non-adoption reasons live in
[the GOTTH component adoption contract](../reference/gotth-stack-adoption.md).
`gotth-authentik` is intended for live desired state after licensing.
`gotth-pg-migrate`, `gotth-release`, and `gotth-infrastructure` require separate
licensed compatibility work. `gotth-jobs` is not placed in the synchronous
login or canonical provisioning transaction.

Authentik is the expected first SCIM client. Authentik calls the GOTTH Mail SCIM endpoint; GOTTH Mail validates requests, enforces domain policy, writes canonical mailbox state, and audits provisioning mutations. Authentik does not write directly to the database or daemon config.

## App-password architecture

App passwords/mail-client tokens:

- are created/revoked/listed through core services
- integrate with Dovecot auth
- are stored as the current GOTTH Mail 1.0 Authentik/Django `pbkdf2_sha256`
  encoded password-hash/verifier strings where password sync or Dovecot
  verification is intended; never plaintext
- expose the secret value only at creation
- emit audit events for create/revoke/use metadata

## Identity UI

GOTTH UI surfaces:

- OIDC/Auth status
- Authentik role/group mapping screens
- SCIM status/test page
- app-password screens
- permission simulator UI

UI mutations go through service/auth/audit layers.

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
