# v2 full-finish blockers

Status: planned/incomplete after full-finish audit.

Required before v2 can honestly return to done:

- Live Authentik authorization-code smoke using a real provider/app/group setup.
- Durable OIDC login state and sessions, with restart/concurrency tests.
- Durable SCIM mailbox/token/app-password storage and Dovecot restart proof.
- App-password client compatibility matrix.
- Honest password verifier contract: PBKDF2-only or true Django/Authenik hasher compatibility.

Current repair closed immediate auth holes and added durable schema contracts, but does not claim these live integrations are complete.

## 2026-07-18 durable OIDC progress

Implemented a real `authn.StateStore` interface with both memory and SQL-backed implementations. `authn.SQLStore` persists OIDC login states and sessions in the new `oidc_login_states` and `sessions` tables. Embedded Postgres tests prove state persistence, browser-binding match, expiry rejection, single-use consume behavior, and session reload through a fresh store wrapper. `api.Server.OIDCStore` now accepts the interface, so production wiring is not type-locked to the in-memory store.

Verification:

- `go test ./internal/authn` passed with embedded Postgres SQL-store coverage.
- `go test ./internal/api ./internal/authn` passed after API store-interface wiring.

Remaining v2 work after this slice:

- Live Authentik provider/app/group bootstrap and authorization-code browser smoke.
- Durable SCIM mailbox/token/app-password runtime wiring and restart proof.
- App-password client compatibility matrix.
- Honest Django/Authenik password verifier contract beyond local PBKDF2 generation.

## 2026-07-18 installed Authentik provider smoke

Danny directed use of the installed Authentik instance. Created/updated a dedicated Authentik application/provider:

- Application slug: `gophermailforge`
- Issuer/discovery: `https://auth.dannyhunn.com/application/o/gophermailforge/`
- Strict redirect URI: `http://127.0.0.1:18080/api/v1/oidc/callback`
- Group created/used: `gophermailforge-admins`
- User `Dan` is a member of `gophermailforge-admins` for live group-claim testing.

Added `scripts/live-authentik-oidc-smoke.sh`. The script requires `GMF_AUTHENTIK_CLIENT_ID` and verifies the live installed provider discovery document, JWKS, and authorization endpoint redirect/state preservation against the strict GopherMailForge callback URI. Client secret is not written to the repository.

Verification run against installed Authentik:

```text
GMF_AUTHENTIK_CLIENT_ID=<redacted-live-client-id> ./scripts/live-authentik-oidc-smoke.sh
live Authentik OIDC smoke passed
issuer=https://auth.dannyhunn.com/application/o/gophermailforge/
redirect_uri=http://127.0.0.1:18080/api/v1/oidc/callback
```

Remaining v2 Authentik work after this slice:

- Browser/passkey authorization-code redemption through GopherMailForge callback with the live client secret supplied out-of-band.
- Live ID token group-claim assertion for `gophermailforge-admins` mapped to the GopherMailForge authorizer.
- Durable SCIM/token/app-password runtime wiring and restart proof.

## 2026-07-18 durable identity/token progress

Implemented SQL-backed persistence for the v2 identity service:

- `Service.DB` can persist and reload mailboxes, API/SCIM tokens, and app-password token verifiers.
- `mailboxes.verifier` was added to the canonical schema so mailbox password verifiers are not memory-only.
- App passwords are stored in the canonical `tokens` table with `kind='app_password'`, mailbox subject, verifier, label, scope JSON, creation time, and revocation timestamp.
- API/SCIM token verifier and scope data are persisted in `tokens` and reloaded after service reconstruction.
- Daemon mailbox and app-password verifier views are rebuilt from loaded SQL state.

Verification:

- `go test ./internal/identity` includes an embedded Postgres restart test proving: provisioned mailbox reload, mailbox password still verifies, app password still verifies after fresh service load, API token scopes reload, and revoked app password remains revoked across another reload.

Remaining v2 work after this slice:

- Wire runtime construction to a configured production database instead of injected tests.
- Live browser/passkey authorization-code redemption through GopherMailForge callback with the installed Authentik provider.
- Live Authentik group claim mapping assertion.
- SCIM client compatibility against installed Authentik SCIM, not only service/API fixtures.
- Password verifier compatibility decision beyond PBKDF2-only local support.

## 2026-07-18 browser-shaped OIDC route progress

Repaired the GopherMailForge OIDC API route shape so the installed Authentik browser/passkey flow can actually complete through a browser:

- `/api/v1/oidc/login?mode=redirect` now creates a browser-binding cookie and redirects to the provider authorization endpoint.
- `/api/v1/oidc/callback` now accepts browser GET callbacks with query `state`/`code`, reads the binding cookie, exchanges the code through the configured exchanger, validates the ID token, sets `gmf_session`, clears the binding cookie, and redirects to the stored post-login target.
- JSON/header-based callback behavior remains available for API tests.
- `api.Server` now accepts an OIDC code exchanger seam so live/runtime wiring can supply the installed Authentik token endpoint/client secret without accepting caller-supplied ID tokens.

Verification:

- `go test ./internal/api` includes a signed-token regression proving redirect login + GET callback + session cookie + redirect-after-login behavior.

Remaining work after this slice:

- Run the interactive browser/passkey login against the installed Authentik provider with GMF running and the live client secret supplied outside the repository.
- Assert live `gophermailforge-admins` group claim mapping to GopherMailForge authorization.

## 2026-07-18 OIDC discovery/JWKS loader progress

Added provider metadata loading to `internal/authn`:

- `FetchDiscovery` retrieves the issuer `.well-known/openid-configuration` document with bounded response size.
- `FetchJWKS` retrieves and validates a non-empty JWKS with bounded response size.
- `DiscoverProvider` fetches discovery, validates issuer/code/RS256 support against `OIDCConfig`, then fetches JWKS.

Verification:

- `go test ./internal/authn` includes an `httptest` provider proving discovery/JWKS fetch and validation.

Remaining live wiring:

- Runtime command/config still needs to call `DiscoverProvider` when starting GMF with the installed Authentik issuer.
- Interactive browser code redemption remains scheduled for manual/passkey verification.

## 2026-07-18 runtime Authentik env wiring progress

Wired `cmd/gophermailforge` startup to the installed Authentik provider configuration via environment variables:

- `GMF_AUTHENTIK_ISSUER`
- `GMF_AUTHENTIK_CLIENT_ID`
- `GMF_AUTHENTIK_CLIENT_SECRET`
- `GMF_AUTHENTIK_REDIRECT_URI`

When configured, startup calls `authn.DiscoverProvider`, validates discovery metadata, loads JWKS, fills `api.Server` OIDC config/authorize endpoint/JWKS, and installs the HTTP code exchanger. Partial env configuration fails closed.

Verification:

- `go test ./cmd/gophermailforge` uses an `httptest` provider to prove environment-driven discovery and server wiring.

Remaining live proof:

- Run `cmd/gophermailforge` with the real installed Authentik env and perform interactive browser/passkey login.
- Assert live group claims from `gophermailforge-admins` map to expected GopherMailForge authorization.

## 2026-07-18 live runtime Authentik redirect smoke

Started the actual `cmd/gophermailforge` runtime locally with installed Authentik environment wiring:

- `GMF_LISTEN=127.0.0.1:18080`
- `GMF_AUTHENTIK_ISSUER=https://auth.dannyhunn.com/application/o/gophermailforge/`
- `GMF_AUTHENTIK_CLIENT_ID=<redacted-live-client-id>`
- `GMF_AUTHENTIK_REDIRECT_URI=http://127.0.0.1:18080/api/v1/oidc/callback`

Probed `http://127.0.0.1:18080/api/v1/oidc/login?mode=redirect&redirect=/done`. Verification:

- runtime returned `302` to installed Authentik authorize endpoint
- redirect host was `auth.dannyhunn.com`
- redirect URI was exactly `http://127.0.0.1:18080/api/v1/oidc/callback`
- `state` and `nonce` were present
- `gmf_oidc_binding` cookie was set, redacted in evidence

This proves real runtime startup/discovery/authorize redirect against the installed Authentik provider. It still does not prove final browser/passkey code redemption; that remains scheduled for interactive testing.

## 2026-07-18 password compatibility contract repair

Closed the overclaim that GopherMailForge had generic Authentik/Django password-hasher compatibility. Current v2 support is now explicitly scoped to Django `pbkdf2_sha256`, matching the checked Authentik/Django default deployment.

Code changes:

- Added `daemon.ValidateDjangoPBKDF2SHA256` as the central validator for stored verifier strings.
- Tightened PBKDF2 validation: supported algorithm only, positive iterations, non-empty salt, and 32-byte SHA-256 digest.
- Kept Dovecot verification local and Authentik-outage independent.
- Mailu import now uses the central PBKDF2 validator instead of a looser shape check.

Contract changes:

- Docs no longer claim generic Django hasher support.
- `argon2`, `bcrypt_sha256`, `scrypt`, `pbkdf2_sha1`, and other Django-recognized algorithms are documented and tested as unsupported until real local verifier support is implemented.

Verification:

- `go test -count=1 ./internal/daemon ./internal/ops` covers valid PBKDF2 verification, unsupported Django hasher rejection, malformed PBKDF2 rejection, and import rejection.

## 2026-07-18 OIDC group-claim mapping progress

Closed the parser seam between Authentik ID-token group claims and GopherMailForge authorization mapping:

- OIDC ID token validation now preserves the `groups` claim on `authn.Identity`.
- Callback completion returns identity groups instead of dropping them.
- Authz regression proves the installed Authentik group name `gophermailforge-admins` maps to `global_admin` when the mapping is verified.

Verification:

- `go test ./internal/authn ./internal/authz` proves group preservation and mapped global-admin authorization.

Remaining live proof:

- Interactive browser/passkey callback must still redeem a real Authentik authorization code and confirm the live ID token includes the expected `gophermailforge-admins` group claim for user `Dan`.

## 2026-07-18 SQL test harness repair

Full gate exposed a test harness failure unrelated to the OIDC group patch: `github.com/fergusstrange/embedded-postgres` defaulted to nonexistent Postgres package versions (`18.3.0`, then pinned `17.5.0` was also unavailable in this environment).

Repair:

- Replaced embedded-postgres test startup with `internal/testpg`, a local Postgres harness using installed `initdb`, `postgres`, and `createdb` binaries.
- Removed the dead embedded-postgres module dependency and transitive xz dependency from `go.mod`/`go.sum`.
- Store/authn/identity SQL tests now use the same local harness and still apply real Postgres migrations.

Verification:

- `go test -count=1 ./internal/authn ./internal/identity ./internal/store` passed.
- `git diff --check -- .` passed.
- `go test -count=1 ./...` passed after the harness repair.
