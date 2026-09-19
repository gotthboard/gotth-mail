# Production notification runtime admission — 2026-09-19

Candidate repair commits: `3f34aa5`, `78ce26e`, `23075c5`, `38db220`

## Admitted behavior

- The Telegram plugin uses the real Bot API in production configuration. The
  in-memory success sink is reachable only through the explicit reference
  fixture switch.
- Core selects Telegram or mandatory-OpenPGP signed email over authenticated
  gRPC with a five-second upper deadline and stores pending/final delivery
  state and typed evidence in PostgreSQL. Production gRPC is restricted to
  loopback or a shared Unix socket; the reference Compose stack uses the
  socket instead of sending bearer credentials over container TCP.
- Telegram alerts are bounded and redacted. Prompt delivery is restricted to
  configured chat IDs and carries a 64-byte-safe one-time approval callback.
- Webhooks require the Telegram secret-token header, exact mapped chat/user
  identity, command-specific authorization, bounded authoritative summaries,
  audit, HTTP-200 application denials, and durable update-ID deduplication.
- Approval tokens are generated from `crypto/rand`; only SHA-256 bindings are
  durable. Replay, expiry, binding mismatch, unauthorized actors, unsupported
  actions, and changed live Postfix snapshots fail closed. The privileged
  helper admits only documented `postqueue -f` and exact-ID `postqueue -i`
  scheduling operations. Leased SQL execution recovers crash/failure paths;
  success consumption and audit commit transactionally.
- The authenticated queue flush/retry API creates an inert SQL approval,
  delivers the bound Telegram prompt, and only then activates the request.
  Creation, activation, lease claims, retries, completion, invalidation, and
  their audit records share transactions. Telegram returns fixed denial text
  and never serializes internal execution or audit errors.
- The owner-only Telegram actor mapping file transactionally replaces the
  configured mapping set, including an explicit empty replacement that
  revokes stale mappings. Operational doctor, certificate, backup, queue,
  abuse/rate-limit, deployment, and plugin-health transitions are polled from
  authoritative state, durably deduplicated, retried after delivery failure,
  and sent through the configured delivery service.
- Plugin health uses the authenticated live gRPC health RPC. Plugin status
  responses fail closed when a probe is unavailable and never serialize
  service credentials or backend diagnostics. Domain summaries come from SQL,
  and read-only HTTP endpoints no longer dispatch alerts as a side effect.
- The reference Compose stack selects exactly one notification sink. The
  default is Telegram; the signed-email overlay replaces it with the mandatory
  OpenPGP sink. Core waits for the selected Unix socket, and the Telegram actor
  map is copied to a private runtime file before startup.
- Migration `0013_notification_approval_binding` rejects legacy unbound
  prompts; `0014_notification_approval_execution` adds recoverable execution
  state; `0015_notification_telegram_updates` adds webhook deduplication; and
  `0016_notification_event_states` adds durable transition/delivery state.

## Cold-review repair

The rejected candidate at `bd52079` had seven material defects: no production
approval initiator, GET-triggered alert spam, non-authoritative command data,
stale actor mappings that could not be revoked, leaked Telegram errors and
discarded audit failures, a Compose profile that did not actually select
signed email, and no container proof of an approved real Postfix mutation.
Commit `3f34aa5` closes all seven rather than narrowing the claims around them.

A fresh cold pass then rejected six remaining defects: exact-message retry
claimed undocumented repeatability, expired `executing` approvals could remain
wedged, missing audit writers allowed command and approval execution, unsupported
Telegram messages and callbacks escaped identity-aware audit, approval creation
was attributed to the prompted Telegram actor instead of the authenticated API
initiator, and an unwired notification gRPC server silently used the local
success sink. Commit `78ce26e` closes those defects. Exact retry now reconciles
an immediate scheduling failure against the live exact queue ID; stale executing
approvals can expire; command, rejection, and mutation paths require audit;
unsupported updates produce bounded denied events; creation records the real
initiator and prompted actor separately; and a missing sink returns gRPC
`Unavailable`.

The next fresh pass found one production-boundary gap: local `postqueue -i`
reconciliation did not cover a successful helper execution whose HTTP 204
response was lost. Commit `23075c5` performs the same exact-ID observation at
the remote client boundary. Only typed not-found proves completion; a present
ID or an unavailable/invalid observation retains the original mutation error.
The regression suite simulates a lost helper response and separately proves
that a still-present queue ID cannot hide a failed retry.

An independent product-contract pass found that the PRD, architecture, and
implementation spec still described config apply, DKIM rotation, rollback,
and break-glass as supported approval workflows while the admitted alpha and
feature decomposition intentionally implement only queue flush/retry. Commit
`38db220` makes that boundary honest: queue approvals are enabled; the other
candidate classes remain rejected until separately specified and proven core
mutation mechanisms exist. The correction does not add a fake generic
chat-to-function path or weaken confirmation policy.

A later trust-boundary pass rejected the statement that every raw Telegram HTTP
request could be mapped to an identity. Authentication failures and malformed
JSON have no trustworthy Telegram actor. The corrected contract requires every
authenticated, well-formed update—including unsupported commands, callbacks,
and update shapes—to map and audit, while transport-authentication and decoding
failures remain outside actor admission and fail closed.

## Verification

- `GOMAXPROCS=4 go test -count=1 -p=2 ./...`
- `GOMAXPROCS=4 go test -race -count=1 -p=2 ./...`
- `GOMAXPROCS=4 go vet ./...`
- `scripts/containerized-notification-plugin-smoke.sh` passed, including
  authenticated initiation, captured prompt, real `postqueue -f`, observed
  SMTP delivery, injected post-mutation ambiguity, stale-lease recovery,
  replay rejection, and exact SQL audit cardinality.
- `scripts/verify-notification-compose.sh`
- normal and signed-email-overlay `docker compose config`
- focused SQL migration, gRPC, Telegram API, webhook, command, approval,
  exact-message retry reconciliation, exact-sender email, and secret-redaction
  tests
- `git diff --check`

## Deployment boundary

No live Telegram request, webhook registration, production credential,
mailbox, queue, deployment, DNS record, signing key, tag, release, or remote
repository changed. A live operator must provide the bot token, chat allowlist,
webhook secret/registration, actor mappings, and production signing-key custody.
