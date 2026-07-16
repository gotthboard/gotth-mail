# v2 identity provisioning root completion evidence

Root feature: `v2.identity-provisioning`
Timestamp: 2026-07-16 12:05 CDT

## Completed children

- `v2.identity-provisioning.oidc-sessions`
- `v2.identity-provisioning.authentik-roles-authz`
- `v2.identity-provisioning.scim`
- `v2.identity-provisioning.app-passwords-ui`

## Root acceptance coverage

- OIDC authorization-code state validation, nonce validation, redirect URI validation, signed token validation, session creation, no unsigned-claim fallback, and no token disclosure are covered by `internal/authn` and API tests.
- Authentik group mappings assign global admin, domain manager, and scoped domain access through `internal/authz` tests and doctor validation.
- Permission simulator explains allow/deny results using request actor/action/resource input.
- SCIM can create, update, list, disable, and patch users through verifier-backed bearer-token authenticated Authentik-compatible flows.
- SCIM failure paths cover malformed JSON, invalid scalar fields, domain policy rejection, empty Operations, unknown paths, unsupported groups, and bad passwords.
- Mailbox passwords and app passwords use Django PBKDF2-SHA256 verifier strings and are verified through the existing daemon `DovecotPassdb` path.
- App-password plaintext secret is returned only at creation and is not returned by list responses.
- Identity/provisioning mutations, denied authorization, failure paths, and Dovecot app-password use success/failure metadata emit audit events without logging secrets.

## Verification

- `git diff --check -- .` passed.
- `go test ./...` passed.

## Coverage gaps

No accepted v2 root coverage gap. The SCIM verification matrix explicitly covers read, replace, non-object rejection, unsupported operations, and id/userName mismatch. Identity UI verification covers SCIM test provisioning, app-password create/list/revoke screens, and permission simulation through service paths.
