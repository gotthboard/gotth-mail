# Postfix runtime enforcement evidence

Date: 2026-09-19 08:45 CDT

State: in progress. This checkpoint does not complete the feature.

## Runtime path admitted in this batch

- authenticated SMTP RCPT policy requests use authoritative PostgreSQL state;
- each original recipient is expanded through its complete reachable alias
  graph and every leaf is checked before admission;
- Postfix long queue IDs are enabled and passed through a dedicated pipe(8)
  transport with the original and final recipient pairs;
- final transport inspects live queue metadata, registers immutable provenance,
  rechecks all remaining recipients, reconciles a whole-message hold on a
  forbidden result, and suppresses relay;
- a separately authenticated Postfix-side helper exposes only inspect and hold;
- the reference stack seeds fixed SQL fixture identities and waits for database
  health before starting policy-dependent services.

## Contracts checked

The transport was checked against the installed official Postfix manuals:

- `SMTPD_POLICY_README` defines the request attributes and action response used
  by the RCPT policy listener;
- `pipe(8)` documents `${queue_id}`, `${original_recipient}`, `${recipient}`,
  `${sasl_username}`, and `${sender}` expansion;
- `postconf(5)` documents `enable_long_queue_ids` and environment export into
  Postfix service processes;
- `postqueue(1)` documents bounded JSON Lines queue inspection;
- `postsuper(1)` documents whole-message `-h queue_id` hold behavior.

No release command is hidden in this helper. Release remains a separate,
confirmed operator operation because it changes delivery state and must be
audited independently.

## Failure behavior

Alias expansion queries only the bounded graph reachable from the original
recipient. A cycle, excessive depth or fan-out, ambiguous object, malformed
target, missing authenticated authority, helper failure, queue mismatch,
policy uncertainty, or invalid response defers closed. A forbidden leaf rejects
the complete original RCPT before queuing.

At final transport, no message bytes are read and no relay is attempted until
queue registration and every recipient policy decision succeeds. Any forbidden
recipient causes the durable hold intent to reconcile through `postsuper -h`;
the gate then returns temporary failure so Postfix retains retry authority.

## Verification

- Focused development-host PostgreSQL tests passed for
  `internal/outboundpolicy`, `internal/postfixgate`, `internal/daemon`,
  `cmd/gotth-mail`, and `cmd/gotth-mail-postfix-gate`.
- Repository-wide `go test -p=1 ./... -count=1`, focused race tests,
  repository-wide `go vet ./...`, and builds of all four commands passed.
- `docker compose config` accepted the reference stack.
- `scripts/containerized-outbound-policy-smoke.sh` built the complete reference
  stack, proved external rejection and same-domain admission at RCPT, injected
  a forbidden message, observed a Postfix long queue ID in the hold queue,
  observed durable SQL state `held`, repeated reconciliation idempotently, and
  found exactly one `queue.policy_hold.applied` audit event.
- The final successful container queue was `4hn9gk6LMXzdWRs`; it was an isolated
  disposable reference Compose project removed by the smoke cleanup trap.
- `git diff --check` passed.

## Remaining feature work

- separately authorized and audited release plus operator diagnostics;
- allowed-relay container proof and retry/replay state changes;
- BCC, list, catch-all, and mixed-recipient hostile cases;
- autoresponder, DSN, bounce, and loop-suppression coverage;
- backup/restore and rollback proof for policy and queue state;
- final documentation/workflow reconciliation and two clean Judge passes.
