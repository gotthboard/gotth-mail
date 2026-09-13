# Architecture — v2 Identity + Provisioning

Source PRD: [PRD-v2-identity-provisioning.md](../prd/PRD-v2-identity-provisioning.md)

## Goal

v2 adds identity and provisioning on top of the working mail core. OIDC is for web/session login. SCIM is for provisioning. App passwords/mail-client tokens are for IMAP/SMTP clients. These must remain separate.

## OIDC architecture

OIDC uses the authorization-code flow.

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

SCIM exposes:

- ServiceProviderConfig
- ResourceTypes
- Schemas
- Users list/create/read/replace/patch/deprovision
- Groups as explicitly unsupported until real group semantics exist

Mapping:

- `userName` -> mailbox email
- `displayName` / `name.formatted` -> displayed name
- `active` -> enabled flag
- `password` -> mailbox password when supplied, stored using the Authentik-compatible Django encoded password-hash format

Validation rejects:

- malformed JSON
- non-object payloads
- invalid scalar identity fields
- unsupported patch operations
- unknown paths
- bad password values

SCIM DELETE disables mailbox by default. It does not delete mail data.

Authentik is the expected first SCIM client. Authentik calls the GOTTH Mail SCIM endpoint; GOTTH Mail validates requests, enforces domain policy, writes canonical mailbox state, and audits provisioning mutations. Authentik does not write directly to the database or daemon config.

## App-password architecture

App passwords/mail-client tokens:

- are created/revoked/listed through core services
- integrate with Dovecot auth
- are stored as Authentik-compatible Django encoded password-hash/verifier strings where password sync or Dovecot verification is intended; never plaintext
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
