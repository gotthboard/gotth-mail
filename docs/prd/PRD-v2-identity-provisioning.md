# GOTTH Mail 1.0 PRD — Identity + Provisioning

Historical workflow ID: `v2.identity-provisioning`. This is a capability
workstream inside the `1.0.0` alpha/beta/stable release line, not product v2.

## Goal

This workstream adds identity and provisioning on top of a working mail core.
OIDC handles web/session login. SCIM handles provisioning. App passwords and
mail-client tokens handle IMAP/SMTP clients. These concepts must stay separate.

## GOTTH component requirements

- `IDP-GOTTH-001`: Runtime OIDC protocol mechanics must use the exact admitted
  `github.com/gotthboard/gotth-oidc/pkg/oidc` revision. GOTTH Mail owns durable
  attempt consumption, browser binding, sessions, cookies, identity records,
  and authorization.
- `IDP-GOTTH-002`: Runtime SCIM protocol mechanics must use the exact admitted
  `github.com/gotthboard/gotth-scim/pkg/scim` revision. GOTTH Mail owns
  authentication, provisioning scope, PostgreSQL storage, mailbox/password/
  audit projection, and product policy.
- `IDP-GOTTH-003`: A reusable GOTTH component is adopted only when its actual
  API fits, its license permits use, its revision is pinned, and consumer
  evidence passes. Placeholder, unlicensed, unrelated, or mechanism-breaking
  components must not be imported for naming consistency.
- `IDP-GOTTH-004`: `gotth-authentik` is MIT-licensed and is the candidate
  desired-state/profile mechanism for the live provider proof. It must not be
  imported until its exact consumer and release contracts are admitted, and
  its use does not authorize a live issuer migration.
- `IDP-GOTTH-005`: The component allocation and exact inspected revisions are
  maintained in [the GOTTH adoption contract](../reference/gotth-stack-adoption.md).

## Scope

### OIDC login

- Provider discovery.
- JWKS handling.
- Authorization-code login flow with callback state validation.
- Nonce generation and validation.
- Exact redirect URI validation against configured public URLs.
- Strict ID token validation:
  - issuer
  - signature
  - subject
  - audience
  - authorized party (`azp`) when present
  - expiry
  - issued-at
  - not-before
- Session creation.
- Failure logging without exposing tokens.
- No unsigned-claim trust fallback.
- S256 PKCE generated and validated by `gotth-oidc`.
- Protected one-time attempt persistence: raw state, nonce, and PKCE verifier
  values are never stored.
- Durable attempt and application-session behavior across process restart.
- A verified OIDC identity may create a product session only when its exact
  issuer and subject resolve to one active SCIM-provisioned mailbox whose
  `externalId` equals the subject and whose address equals the verified OIDC
  email after case folding. Missing, ambiguous, disabled, or mismatched
  bindings fail closed.
- Application sessions reference the durable `identity_refs` row by foreign
  key. Concatenated `issuer|subject` strings are not identity records.

### Authentik role mapping

Mandatory mappings for:

- global admins
- domain managers
- scoped domain access

Requirements:

- group/role mapping is generated or documented as part of the required Authentik profile.
- role mapping is verified by tests/doctor.
- no local manual edits should be required to assign global admin/domain manager/scoped access.
- Authentik is required for identity flows but remains adjacent, not embedded.
- Authentik outage may break new SSO/provisioning actions but must not break mail delivery or daemon lookup paths.
- ID-token `groups` claims are not role authority. `gotth-oidc` deliberately
  excludes authorization-shaped claims; roles come only from durable role
  bindings populated by the admitted provisioning/profile path.

### Permission simulator full coverage

- Explain actor/action/resource decisions.
- Cover local admin, API token, OIDC subject, SCIM client, system actor, and break-glass actor.
- Explain global admin, domain manager, scoped-domain access, and denied results.
- UI/API/CLI can use the same explanation model.

### SCIM provisioning

- ServiceProviderConfig.
- ResourceTypes.
- Schemas.
- Users list/create/read/replace/patch/deprovision.
- Groups use the pinned `gotth-scim` protocol surface only after every member
  value is validated as a live opaque User ID in the same provisioning scope.
  Nested Groups are rejected for 1.0. Group storage is non-authoritative until
  the separately admitted Authentik profile maps exact group resources to
  durable product roles.
- Map:
  - `userName` to mailbox email
  - `displayName`/`name.formatted` to displayed name
  - `active` to enabled/disabled
  - `password` to mailbox password when supplied, hashed into the current
    GOTTH Mail 1.0 Authentik/Django `pbkdf2_sha256` encoded password format
- Reject malformed JSON, non-object payloads, invalid scalar identity fields, unsupported patch operations, unknown paths, and bad passwords.
- SCIM DELETE disables mailbox by default; it does not delete mail data.
- A User referenced by a live Group cannot be deleted until the manager removes
  that membership. Group replacement updates its normalized membership index
  atomically with the SCIM resource and audit.
- Authentik-compatible provisioning path.
- Existing email-keyed mailboxes are admitted through an explicit
  preview/confirm adoption operation. The operator supplies the exact mailbox,
  stable Authentik subject, SCIM scope, and manager. The operation must use
  `gotth-scim` validation, opaque-ID generation, reconciliation, and the
  product PostgreSQL transaction adapter; it must never derive an ID or
  subject from the mailbox address.
- Adoption preserves the existing mailbox row, verifier, enabled state,
  creation time, and mail data. It attaches one newly generated opaque SCIM
  User ID and records the redacted SCIM audit in the same transaction.
- Preview output contains no verifier or credential material and produces a
  deterministic confirmation digest over the exact mailbox row/version and
  requested ownership. Apply rechecks that state under lock and fails closed
  if it drifted, is already owned, is tombstoned, or conflicts with another
  subject.
- Adoption does not manufacture an OIDC identity reference. The first
  independently verified OIDC callback must still prove issuer, subject, and
  email continuity before it can create `identity_refs` or a session.

### App passwords / mail-client tokens

- Create/revoke/list app passwords.
- Preserve a stable opaque public credential ID and a separate human label
  across process restart; neither may be reconstructed from the other.
- Permit at most eight active app passwords per mailbox. This bounds the
  current Dovecot PBKDF2 verification cost while preserving the existing
  opaque one-time secret format.
- Scoped use where practical.
- Dovecot integration.
- Store mailbox-password and app-password/mail-client token secrets as the
  current GOTTH Mail 1.0 Authentik/Django `pbkdf2_sha256` encoded
  password-hash/verifier strings where password sync or Dovecot verification
  is intended; never plaintext.
- Audit events for create/revoke/use metadata.
- On the configured PostgreSQL path, create/revoke state and the corresponding
  success audit event commit in one transaction. A success event may never
  outlive a rolled-back credential mutation.
- Never expose token values after creation.
- OIDC is not IMAP/SMTP auth; mail clients need app passwords or compatible credentials.

### Identity UI

- OIDC/Auth status.
- Authentik role/group mapping screens.
- Read-only SCIM capability/status page linked to the real `gotth-scim`
  endpoint; no browser-only shortcut may bypass that endpoint.
- App-password screens only after a durable OIDC session is authoritatively
  bound to its mailbox and roles. Until then the UI must say unavailable and
  direct authenticated automation to the scoped API instead of presenting
  mutation forms an ordinary browser cannot authenticate.
- Permission simulator UI.

### Identity-related plugin checks

- Authentik health in doctor.
- Plugin service identity checks.
- No plugin can grant identity authority.
- Role mapping remains core.

## Non-goals

- No custom identity provider.
- No embedding Authentik.
- No generic policy framework.
- No mailbox provisioning that bypasses GOTTH Mail validation.

## Acceptance criteria

- OIDC login works with authorization-code state validation, nonce validation, exact redirect URI validation, and strict token validation.
- Malformed/unverifiable OIDC tokens and invalid callback state/nonce values are rejected.
- Authentik group/role mappings assign global admin, domain manager, and scoped domain access.
- Permission simulator explains allow/deny results for identity-backed actors.
- SCIM provisioning can create, update, list, disable, and patch users through Authentik-compatible flows.
- SCIM failure paths are tested.
- SCIM Groups can be created, read, listed, replaced, patched, and deleted with
  same-scope opaque User membership; missing/cross-scope/User-delete conflicts
  fail without partial mutation. Group existence alone grants no role.
- The `gotth-scim` PostgreSQL adapter passes the exported store conformance
  check and product restart/concurrency/migration/backup/restore tests.
- SCIM resources use opaque persistent IDs; an email address is never the
  resource ID.
- A reviewed legacy-mailbox adoption survives restart, preserves the existing
  mailbox UUID/verifier/data ownership, is idempotent only for the exact
  manager-owned desired identity, and rejects stale confirmation, duplicate
  subject, duplicate mailbox ownership, and tombstones without partial state.
- App passwords/mail-client tokens work for Dovecot auth and are stored as the
  current GOTTH Mail 1.0 Authentik/Django `pbkdf2_sha256` encoded
  password-hash/verifier strings or explicitly documented verifier-only
  records; never plaintext.
- App-password ID, label, verifier, mailbox ownership, creation time, and
  revocation survive restart; active credentials are bounded to eight per
  mailbox.
- PostgreSQL app-password create/revoke and success audit admission are atomic.
- Every identity/provisioning mutation is audited.
- A SCIM disable or delete revokes every active application session bound to
  that mailbox in the same database transaction. Re-enabling a mailbox never
  revives an old session.
- A bound OIDC session may list, create, and revoke app passwords only for its
  own active mailbox. Browser mutations require the session cookie plus a
  separate CSRF secret; neither value is accepted as an IMAP/SMTP credential.
