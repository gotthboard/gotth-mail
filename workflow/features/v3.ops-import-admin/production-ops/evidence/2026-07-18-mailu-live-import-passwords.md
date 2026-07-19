# v3 Mailu live import password preservation evidence

Status: repaired for configured SQL paths; v3 root still depends on full repository verification and any remaining parent workflow blockers.

## Scope

Use the local/test Mailu reference fixture only for GopherMailForge import compatibility. Do not deploy a production mail server. Do not expose public mail ports for this work.

## Source facts

- A minimal local Mailu fixture was started under `/tmp/gmf-mailu-fixture` using Mailu admin plus Redis only.
- `flask mailu config-export --json` emits top-level `domain`, `user`, `alias`, and `relay` arrays.
- Non-secret export redacts sensitive values, including user password hashes; those redacted values are not admissible for password preservation.
- `flask mailu config-export --secrets --json` emits Mailu user password hashes in Passlib `bcrypt-sha256` format.
- Bryce's previous production migration proved the Authentik-compatible preservation mechanism: store the original Mailu Passlib hash under a wrapper prefix, `mailu_bcrypt_sha256$<original-mailu-passlib-hash>`, and load an Authentik custom password hasher that strips the wrapper and verifies the original Passlib hash. This is not a Django `bcrypt_sha256` conversion.

## Implementation changes

- `internal/ops/v3.go` now parses both legacy synthetic candidate arrays and live Mailu `config-export --json` objects.
- Live export parsing adopts domains, users, aliases, and relays.
- Alias import preserves multiple Mailu destinations instead of collapsing aliases to one target.
- Mailu user password hashes from secret exports are preserved as `mailu_bcrypt_sha256$...`.
- Redacted Mailu password exports fail validation for user password preservation.
- Unknown/non-recorded verifier algorithms remain incompatible.
- `ops.SQLImportStore` applies admissible Mailu import previews into canonical SQL `domains`, `mailboxes`, `aliases`, and `relays` tables when a DB is configured.
- The SQL import path reloads daemon state from SQL after commit and verifies imported recipients against that actual persisted state.
- `/api/v1/imports/mailu/apply` uses the SQL import path and durable SQL audit writer when `api.Server.AuditDB` is configured; memory fallback remains for non-SQL callers/tests.
- Local Dovecot verifier support is not broadened: wrapped Mailu hashes are migration-preservation values for an Authentik custom hasher, not a claim of native local secret verification.

## Fixtures

- `test/fixtures/mailu/config-export.json`: redacted non-secret Mailu export shape; used to prove redacted password values are rejected.
- `test/fixtures/mailu/config-export-secrets.json`: local Mailu test fixture secret export; contains only fixture hashes generated for `example.test`, not production secrets.

## Verification

- `go test -count=1 ./internal/ops` passed after adding live Mailu export fixture coverage.
- `go test -count=1 ./internal/ops ./internal/api` passed after adding canonical SQL import apply and API route coverage.

## Remaining blocker

This closes the Mailu fake-parser/password-preservation and canonical SQL apply blocker for configured paths. Full repository verification must pass before commit/admission.
