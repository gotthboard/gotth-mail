# Implementation Spec — v2 Identity + Provisioning

Source PRD: [PRD-v2-identity-provisioning.md](../PRD-v2-identity-provisioning.md)
Source architecture: [architecture/v2-identity-provisioning.md](../architecture/v2-identity-provisioning.md)

## Goal

Add OIDC web/session login, Authentik role mapping, SCIM provisioning, app-password/mail-client token management, identity UI, and full permission simulator coverage.

OIDC, SCIM, and IMAP/SMTP credentials must stay separate.

## OIDC login

Flow:

```text
start_login -> redirect_to_provider -> callback -> validate_state -> exchange_code -> validate_id_token -> map_identity -> create_session
```

OIDC login state is stored in `oidc_login_states`:

- `state_id` primary key
- `nonce` not null
- `browser_binding_hash` not null
- `redirect_after_login`
- `created_at`
- `expires_at`
- `used_at`

`state_id` is single-use. The callback must mark it used in the same transaction that accepts the callback.

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

Failures return safe errors and log no tokens.

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
```

Groups return explicit unsupported behavior until real group semantics exist.

SCIM requests authenticate as a `scim_client` actor using a verifier-backed bearer/API token. Every create/update/patch/deprovision request runs through core authorization and domain policy before canonical mailbox state is admitted.

User mapping:

- `userName` -> mailbox email
- `displayName` or `name.formatted` -> display name
- `active` -> enabled flag
- `password` -> mailbox password when supplied

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

Authentik is the first expected SCIM client. Authentik calls GopherMailForge SCIM; GopherMailForge validates, authorizes, writes canonical mailbox state, and audits mutations. Authentik never writes directly to DB or daemon config.

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

- store verifier/hash only
- never log plaintext secret
- never return secret after creation
- revocation sets `revoked_at`
- Dovecot passdb validates against verifier

Audit events:

- create
- revoke
- successful use metadata
- failed use metadata without secret

## Identity UI

GOTTH pages:

- OIDC/Auth status
- Authentik role/group mapping
- SCIM status/test
- app-password list/create/revoke
- permission simulator

All mutations use service/auth/audit paths.

## Plugin identity boundary

Plugin service identity authenticates plugin admission only. It cannot grant roles, create users, or bypass core validation.

## Verification

Required tests:

- OIDC state, nonce, redirect URI, issuer, signature, subject, audience, azp, exp, iat, nbf validation
- invalid state/nonce/token negative tests
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
- app-password create/revoke/list/Dovecot auth with verifier-only storage
- every identity/provisioning mutation audited
- `git diff --check`
- `go test ./...`
