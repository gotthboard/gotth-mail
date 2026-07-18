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
