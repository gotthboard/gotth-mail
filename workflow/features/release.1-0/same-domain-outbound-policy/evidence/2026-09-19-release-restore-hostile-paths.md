# Release, restore, and hostile-path evidence

Date: 2026-09-19 09:28 CDT

State: implementation complete; final repository gates and cold admission
reviews remain before workflow completion.

## Release boundary

- A release preview re-evaluates every immutable remaining recipient against
  current authoritative source objects and binds its SHA-256 confirmation to
  queue identity, recipient/source digests, and every current scope/revision.
- Confirmed release takes a per-queue PostgreSQL advisory lock, recomputes the
  preview, verifies live held metadata, commits an audited release intent,
  invokes only `postsuper -H <validated-long-queue-id>`, verifies the exact live
  message is no longer held, and commits `released` plus an audit event.
- Failure after intent remains visible as `release_error`; a verified repeat is
  idempotent and a stale confirmation is rejected.
- The release bearer is distinct from the delivery helper bearer. Unit and
  container tests prove neither credential can perform the other's mutation
  class. Postfix `import_environment` and `export_environment` omit the release
  credential, so pipe services cannot acquire it.

## Restore and recipient-set behavior

- Backup capture and isolated SQL restore preserve and verify domain policy
  scopes/revisions, immutable mailbox and alias IDs, system-sender bindings,
  queue identity digests, authoritative sources, recipients, attempts, and hold
  state. A local non-isolated restore cannot falsely claim policy verification.
- Webmail persists To, CC, and BCC. Submission normalizes and de-duplicates the
  full envelope set, checks every expanded recipient before signing or SMTP,
  rejects the whole draft on one forbidden BCC, emits To/Cc headers only, and
  sends BCC solely in the SMTP envelope.
- Retry and replay tests re-run current policy rather than treating initial
  acceptance as authority. Mixed final recipients hold the complete queue
  message and suppress relay.

## Expansion and automatic-mail behavior

- The authoritative alias mechanism classifies exact local aliases, external
  forwards, one-to-many lists, and wildcard catch-alls in immutable queue
  provenance. Exact aliases win over a domain catch-all; reachable cycles,
  omitted branches, ambiguity, excessive depth, and excessive fan-out fail
  closed.
- Notifications, autoresponders, DSNs, and bounces share a closed automatic
  disposition: forbidden becomes terminal `policy_blocked`, uncertainty
  retries, and neither outcome asks for another bounce. The notification
  runtime uses this contract before signing or SMTP.
- Rejection audit stores only the recipient domain, decision reason, and policy
  revisions; no local part, message body, credential, or signing material is
  persisted.

## Real reference-stack proof

`scripts/containerized-outbound-policy-smoke.sh` built the reference stack and:

1. rejected an authenticated external RCPT and admitted a same-domain RCPT;
2. accepted inbound mail to `forward@example.test` independently of the
   domain's outbound restriction;
3. expanded that local forward to an external recipient, registered immutable
   alias provenance, and held the complete long-ID queue message;
4. repeated reconciliation without duplicating the hold audit;
5. rejected the helper credential at the release-preview route;
6. changed the disposable fixture policy to `unrestricted`, previewed with the
   independent release credential, and explicitly released the exact message;
7. observed exactly one release-start and one released audit event; and
8. submitted one new unrestricted message with two external recipients through
   a single whole-message `pipe(8)` request and observed exactly one SMTP DATA
   transaction containing both envelope recipients.

The final disposable held queue ID was `4hnCPv0X6pzfB5b`. The cleanup trap
removed the entire Compose project and its volumes.

## Verification completed in this checkpoint

- focused development-host PostgreSQL suites for changed packages and commands;
- container build's repository-wide test run;
- two successful outbound-policy container smokes, including the final expanded
  inbound-forward and allowed-relay version;
- shell syntax checks for the smoke and SMTP sink;
- local focused tests and `git diff --check`.

## Cold-review repair

The first cold pass found a real time-of-check/time-of-use race between the
final policy recheck and `postsuper -H`. Release now holds PostgreSQL share
locks on the complete policy-authority table set across the external release
and post-release verification. A development-host concurrency test pauses at
the helper boundary, proves a domain policy update times out instead of
crossing the release, resumes the helper, and observes successful completion.
Both the focused normal and race suites passed after the repair.

The next cold pass found that a wildcard catch-all targeting an enabled local
mailbox could be re-applied to that mailbox instead of terminating expansion,
and that multi-query backup capture did not use one database snapshot. The
catch-all query now excludes enabled local mailbox targets, with a PostgreSQL
regression test, and backup capture now uses one repeatable-read read-only
transaction. Focused normal and race suites for outbound policy and operations
passed after both repairs.

A later fresh pass found a cardinality mismatch between Postfix and the gate:
the transport forced one recipient per pipe invocation, but every invocation
inspected and relayed the complete queue recipient set. The transport now uses
Postfix's documented multi-recipient macro expansion, and admission rejects an
incomplete or foreign final-recipient argument set. The container smoke's SMTP
sink records accepted transaction recipient counts and proved exactly one
two-recipient handoff. Focused normal and race suites passed on the corrected
canonical worktree.

The first final cold pass then found that `AdminService` had no authenticated
product route, so an administrator could not actually preview or apply the
domain policy, and that restored mailbox verifier/quota drift was omitted from
verification. Bounded `/api/v1/domains/outbound-policy/{preview,apply}` routes
now require a domain-scoped administrator token; apply also requires the exact
preview digest and a valid correlation ID. Restore verification compares the
captured verifier and quota. Focused API/outbound-policy/operations normal and
race suites passed, including new authorization and corruption tests.

The repaired-tree pass found that unauthenticated inbound queue admission
treated a reverse path matching a hosted mailbox as authoritative local sender
provenance. That trusted spoofable envelope text and could inject an unintended
governing domain into a legitimate forward. Admission now derives sender
authority only from an authenticated mailbox or durable system-sender binding;
unauthenticated inbound mail is governed solely by the local expansion objects
that created the outbound delivery. Focused normal and race suites passed with
a spoofed-local-sender regression test.

## Remaining admission work

- repository-wide serial, race, vet, command-build, Compose-render, and workflow
  traceability gates on the final tree;
- one cold Judge pass, repair of any real finding, then two independent fresh
  clean passes as required by the feature handoff discipline.
