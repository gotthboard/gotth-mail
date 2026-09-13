# GOTTH Mail PRD — v2 Identity + Provisioning

## Goal

v2 adds identity and provisioning on top of a working mail core. OIDC handles web/session login. SCIM handles provisioning. App passwords/mail-client tokens handle IMAP/SMTP clients. These concepts must stay separate.

## Scope

### v2.1 OIDC login

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

### v2.2 Authentik role mapping

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

### v2.3 Permission simulator full coverage

- Explain actor/action/resource decisions.
- Cover local admin, API token, OIDC subject, SCIM client, system actor, and break-glass actor.
- Explain global admin, domain manager, scoped-domain access, and denied results.
- UI/API/CLI can use the same explanation model.

### v2.4 SCIM provisioning

- ServiceProviderConfig.
- ResourceTypes.
- Schemas.
- Users list/create/read/replace/patch/deprovision.
- Groups explicitly unsupported until real group semantics exist.
- Map:
  - `userName` to mailbox email
  - `displayName`/`name.formatted` to displayed name
  - `active` to enabled/disabled
  - `password` to mailbox password when supplied, hashed into the Authentik-compatible Django encoded password-hash format
- Reject malformed JSON, non-object payloads, invalid scalar identity fields, unsupported patch operations, unknown paths, and bad passwords.
- SCIM DELETE disables mailbox by default; it does not delete mail data.
- Authentik-compatible provisioning path.

### v2.5 App passwords / mail-client tokens

- Create/revoke/list app passwords.
- Scoped use where practical.
- Dovecot integration.
- Store mailbox-password and app-password/mail-client token secrets as Authentik-compatible Django encoded password-hash/verifier strings where password sync or Dovecot verification is intended; never plaintext.
- Audit events for create/revoke/use metadata.
- Never expose token values after creation.
- OIDC is not IMAP/SMTP auth; mail clients need app passwords or compatible credentials.

### v2.6 Identity UI

- OIDC/Auth status.
- Authentik role/group mapping screens.
- SCIM status/test page.
- App-password screens.
- Permission simulator UI.

### v2.7 Identity-related plugin checks

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
- App passwords/mail-client tokens work for Dovecot auth and are stored as Authentik-compatible Django encoded password-hash/verifier strings or explicitly documented verifier-only records; never plaintext.
- Every identity/provisioning mutation is audited.
