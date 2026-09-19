# Same-domain outbound policy core and administration evidence

Date: 2026-09-19 07:00 CDT

State: in progress. This record does not complete the feature.

## Scope admitted in this batch

- strict canonical domain normalization and exact-domain policy decisions;
- fail-closed submission and transport outcomes;
- compatibility-preserving durable policy scope and revision migration;
- revision- and digest-bound preview/confirm administration;
- serializable update plus atomic redacted audit;
- explicit workflow handoff from the deployment-blocked live-identity feature.

## Runtime boundary

- Go: 1.26.6 on `development`.
- IDNA library: `golang.org/x/net` v0.56.0.
- Profile: explicit `MapForLookup`, Bidi rule, DNS-length verification, and
  non-transitional mapping.
- The library documents that conversion may return a sanitized partial value
  with an error. GOTTH Mail discards that value and fails closed.
- Policy comparison uses lowercase DNS A-labels after removing one terminal
  root dot. Subdomains and other hosted domains remain unequal.

## Verification

- Baseline before edits: `go test ./...` passed.
- Every production unit began with an expected-red focused test.
- `go test ./internal/outboundpolicy -count=1` passed.
- `go test ./internal/store -count=1` passed.
- PostgreSQL tests cover existing-row default preservation, invalid enum and
  revision rejection, bounded alias impact counts, wrong and stale
  confirmation rejection, successful revision increment, address-free audit,
  and rollback when the audit insert fails.
- `go test -race ./internal/outboundpolicy ./internal/store -count=1` passed.
- `go vet ./internal/outboundpolicy ./internal/store` passed.
- `go test -p=1 ./... -count=1` passed across the repository.
- Focused statement coverage measured 91.9% after hostile-path additions. The
  remaining uncovered branches are database-driver begin/query/scan/commit
  failures and impossible JSON-marshal failure for a fixed scalar plan; they
  require an injected SQL driver rather than product behavior. Audit failure,
  stale state, corrupt stored state, no-op apply, invalid/oversized input, and
  PostgreSQL constraint failures are covered directly.
- The first unbounded full-suite attempt encountered the development host's
  pre-existing System V shared-memory object ceiling: 4,094 unattached
  56-byte PostgreSQL test remnants owned by the development user. They were
  removed without touching two attached segments; the serialized rerun then
  passed. This was host hygiene, not a product-code failure.

## Analysis records

- Context broker 0.1.0, state
  `17275d5a1572d0f82d788b6988e0e3cf83cdd4c1`, base
  `fb1fcb893bf47aa00014c1a55b156603d463eb9a`, 12 files / 100 lines / 30000
  bytes. The packet reached its byte bound and was treated as truncated
  navigation evidence only.
- Graphify 0.9.32 code-only graph at
  `/home/linus/.cache/openclaw-code-index/gotth-mail/17275d5a1572d0f82d788b6988e0e3cf83cdd4c1/graphify/graphify-out/graph.json`,
  SHA-256 `936d7f74c8f87bbeb06c46ae5583644cfdae3a2a1b187fc4aa830980be73f301`.
  It contains 1,859 nodes and 4,590 edges. SQL extraction was unavailable, so
  migration conclusions were verified directly from SQL, the migration
  runner, and PostgreSQL tests.

## Remaining feature work

- durable queue provenance and policy-hold state;
- authoritative mailbox/envelope/system/expansion-source resolution;
- daemon HTTP and generated Postfix integration;
- atomic web/API recipient-set enforcement;
- notifications, autoresponders, DSNs, and bounce suppression;
- retry, flush, replay, restore, final-handoff checks, and narrow hold/release
  helper;
- diagnostics, backup/restore/rollback evidence, container smoke, performance
  admission, full race/vet/build gates, and Judge-loop completion.
