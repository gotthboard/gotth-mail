# v2 admission repair evidence

Root feature: `v2.identity-provisioning`
Timestamp: 2026-07-18 CDT

## Repair slice

Layered vertical slice: OIDC callback/session boundary plus provisioning/app-password audit authority.

## What changed

- Replaced API callback acceptance of caller-supplied `id_token` with an authorization-code exchange seam (`CodeExchanger` / token endpoint request) before token validation.
- Hardened OIDC random token generation so failed entropy is an error, not silently ignored.
- API login callback now sets a `gmf_session` HttpOnly Secure SameSiteStrict cookie and no longer returns the session ID in JSON.
- Identity audit dependency now uses the `audit.Writer` interface, allowing fail-closed writer tests instead of depending on an in-memory concrete type.
- SCIM and app-password mutations now write success audit records before committing state; audit failure prevents the mutation.
- API tokens no longer imply wildcard cross-mailbox authority; app-password API authorization requires scoped permissions for the target mailbox.
- Dovecot passdb audit action distinguishes primary mailbox password use from app-password use.

## Verification

- `git diff --check -- .` passed.
- `go test ./...` passed.
- Relevant focused tests passed as part of `go test ./...`:
  - OIDC authorization-code exchange/callback/session-cookie behavior in `internal/authn` and `internal/api`.
  - Audit-failure mutation rejection and mailbox-scoped app-password authorization in `internal/identity` and `internal/api`.

## Remaining gaps

- Live Authentik browser integration is still not proven here; this repair proves the code-exchange seam and callback behavior with local fixtures.
