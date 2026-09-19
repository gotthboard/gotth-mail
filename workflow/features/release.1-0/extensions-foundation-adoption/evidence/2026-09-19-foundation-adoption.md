# GOTTH Extensions foundation adoption — 2026-09-19

Candidate base: `cf4d639`

## Scope

- Pin reviewed `github.com/gotthboard/gotth-extensions` commit
  `3822dd722bc8606b8843d0a68c7c3e9f598d9ccc` through immutable pseudo-version
  `v0.0.0-20260914032833-3822dd722bc8`.
- Use the public package for manifest/grant validation, canonical digests,
  exact subset negotiation, session fingerprints, and lifecycle transitions.
- Preserve the upstream `gotth.extensions.v1.ExtensionControl` wire contract
  in consumer-local generated bindings and expose only authenticated
  challenge-bound handshake plus session-bound health.
- Bind the existing Webmail, DNS, certificate, backup, Telegram, and signed
  email mechanisms without changing their Mail-owned seam RPCs.
- Make configured production notification health use the foundation exchange.

## Trust boundary

The foundation session contains identifiers, granted capabilities, interface
versions, and named secret slots only. It contains no secret value, transport
credential, generic payload, host callback, process-control method, event bus,
or product mutation. Existing service-token metadata remains the transport
authentication boundary. GOTTH Mail remains authoritative for routing,
supervision, policy, mutation, audit, update, and rollback.

## Relevant coverage

- exact module pin and no local replacement;
- public consumer negotiation and capability-expansion rejection;
- descriptor proof that control exposes only Handshake and Health and contains
  no generic authority-bearing fields;
- exact built-in manifest/grant/session and named-secret-slot projections;
- deterministic distinct instance IDs;
- valid and invalid lifecycle transitions;
- authenticated live handshake and health;
- wrong-token, missing-deadline, stale-session, short-challenge, malformed
  correlation, entropy-failure, hostile-response, invalid-health-code, missing
  binding, and cross-registration failure-isolation paths;
- existing seam tests and containerized plugin/backend smoke.

## Verification

- `GOMAXPROCS=4 go test -count=1 -p=2 -race ./internal/plugin ./internal/notifyruntime ./cmd/gotth-mail ./cmd/gotth-mail-plugin ./test/contract` — passed.
- `GOMAXPROCS=4 go vet ./...` — passed.
- `GOMAXPROCS=4 go test -count=1 -p=2 ./...` — passed.
- `COMPOSE_PROGRESS=plain scripts/containerized-notification-plugin-smoke.sh`
  — passed; this includes the live authenticated foundation exchange, signed
  email, real Postfix approval, and ambiguous-delivery recovery.
- consumer-local control protobuf compared byte-for-byte after removing only
  the provenance comment and consumer-local `go_package`; no wire difference.
- `git diff --check` — passed.

Foundation coverage is 100% by function and statement for every reachable
function except `NewFoundationBinding` at 90.9%. Its two uncovered returns are
defensive checks for the pinned library rejecting an exact grant/profile or
the fixed `discovered -> starting -> ready` sequence immediately after the
same library validated those inputs. Reaching them requires replacing or
corrupting the dependency contract, so no dishonest test hook was added.

## Deliberate boundary

This feature does not implement the persisted extension registry, encrypted
installation secret store, process supervisor, administrator routes/UI,
update, rollback, uninstall, or secret deletion. Those belong to the declared
`v3.ops-import-admin.extension-management-ui` feature. No tag, release, push,
deployment, live credential, or external service mutation is part of this
admission.
