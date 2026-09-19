# Durable queue and submitter enforcement evidence

Date: 2026-09-19 08:15 CDT

State: in progress. This checkpoint does not complete the feature.

## Scope admitted in this batch

- durable Postfix queue provenance and whole-message policy-hold state;
- SQL-authoritative mailbox, envelope-sender, system-sender, and expansion
  source resolution;
- current-revision re-evaluation at the transport boundary;
- bounded Postfix queue inspection and narrow whole-message hold invocation;
- idempotent, lock-serialized hold reconciliation with visible retry errors;
- daemon HTTP, webmail, and signed-email notification policy boundaries.

## Postfix contracts checked

The implementation was checked against the installed official Postfix manual
pages rather than inferred from folklore:

- `postconf(5)` documents long queue IDs and the required alphabet/shape;
- `postqueue(1)` documents `-j` JSON Lines output and that the queue can change
  while it is listed;
- `postsuper(1)` documents `-h queue_id` as a whole-message hold and `-H` as an
  independent release operation.

The helper surface accepts one validated long queue ID. It exposes no shell,
delete, expiry, arbitrary selector, `ALL`, or raw-argument path. The queue
fingerprint binds instance identity, queue ID, arrival time, message size,
canonical sender, and the sorted recipient set while remaining stable across a
move to the hold queue.

## Failure and transaction behavior

Policy state commits before any external Postfix hold. Reconciliation takes a
per-queue PostgreSQL advisory lock, persists `reconciling`, verifies live queue
metadata, invokes the narrow helper, verifies the exact queue metadata again,
then records `held`. A helper, metadata, audit, or database failure remains
visible and retryable. Idempotent repeats do not reapply a completed hold.

Queue registration is exact and immutable. Reuse with a different arrival
fingerprint, sender, recipient set, or source set is rejected. Transport callers
cannot replace queue provenance with supplied governing domains. Missing,
renamed, disabled, or corrupt authoritative objects fail closed.

## Submitter behavior

- Webmail resolves and checks the complete recipient set before signing or
  SMTP; one forbidden recipient rejects the entire draft.
- Signed-email notifications use a durable `system:<address>` identity. A
  policy rejection is a terminal suppressed disposition; unavailable policy is
  retryable. Neither path reaches signing or SMTP.
- The notification plugin uses a bounded internal HTTP client with strict
  decision/reason/revision parsing and correlation propagation.

## Verification

- Focused development-host package tests passed for `internal/outboundpolicy`,
  `internal/daemon`, `internal/render`, `internal/webmail`, `internal/store`,
  `internal/notifyruntime`, `cmd/gotth-mail`, and `cmd/gotth-mail-plugin`.
- Focused `go vet` passed for the same packages.
- `go test -p=1 ./... -count=1`, repository-wide `go vet ./...`, and builds
  of `gotth-mail`, `gotth-mailctl`, and `gotth-mail-plugin` passed on the
  development host.
- Focused race tests passed for the changed runtime packages and commands.
- PostgreSQL coverage includes exact registration/reload, immutable mismatch,
  source resolution, same-domain and forbidden decisions, conflicting
  restricted sources, post-accept policy changes, durable system-sender
  binding, hold success, helper failure, metadata mismatch, audit failure, and
  idempotent retry.
- Postfix boundary coverage includes bounded JSON Lines parsing, duplicate or
  changing listings, invalid queue IDs/paths, command/output failure, and fixed
  `postsuper -h` arguments.
- `git diff --check` passed.

## Remaining feature work

- generated Postfix submission and final-transport integration with long queue
  IDs enabled;
- real queue registration/retry/replay/restore and container hold proof;
- explicit separately authorized release and operator diagnostics;
- alias/forward/list/BCC/catch-all integration proof plus autoresponder,
  DSN, and bounce-loop suppression;
- backup/restore/rollback proof and complete audit-redaction checks;
- complete race/vet/build/container gates and two independent clean Judge
  passes before feature handoff.
