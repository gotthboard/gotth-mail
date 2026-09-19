# Release, restore, and hostile-path evidence

Date: 2026-09-19 09:28 CDT

State: complete. Repository gates, reference-stack proof, and the required two
independent final clean admission reviews passed on commit `ba851a9`.

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
- Postfix null-sender DSN/bounce traffic selects a dedicated final gate
  transport carrying a fixed durable mailer-daemon system identity. Queue
  inspection canonicalizes Postfix's `MAILER-DAEMON` JSON display to `<>`;
  admission then persists that exact null reverse path with system-sender
  provenance before the final policy decision and relay. The pipe also carries
  Postfix's documented `client_address`: an inbound null-sender message has a
  client address and therefore receives no system identity, instead retaining
  only the authoritative local expansion provenance that caused forwarding.
- Rejection audit stores only the recipient domain, decision reason, and policy
  revisions; no local part, message body, credential, or signing material is
  persisted.

## Real reference-stack proof

`scripts/containerized-outbound-policy-smoke.sh` built the reference stack and:

1. rejected an authenticated external RCPT and admitted a same-domain RCPT;
2. accepted inbound mail to `forward@example.test` independently of the
   domain's outbound restriction;
3. expanded that local forward to two external recipients, registered immutable
   list provenance, and held the complete long-ID queue message without
   assigning the inbound null sender a system identity;
4. repeated reconciliation without duplicating the hold audit;
5. rejected the helper credential at the release-preview route;
6. changed the disposable fixture policy to `unrestricted`, previewed with the
   independent release credential, and explicitly released the exact message;
7. observed exactly one release-start and one released audit event; and
8. flushed that same released queue message through a single whole-message
   `pipe(8)` request and observed exactly one SMTP DATA transaction containing
   both envelope recipients;
9. authenticated a signed notification as its durable `system:` identity and
   proved that identity survived submission and final transport; and
10. injected a Postfix null-sender automatic message, observed exactly one
    relay transaction, and verified exactly one immutable
    `system:mailer-daemon@example.test` provenance row.

The final disposable held queue ID was `4hnGXw0JJWzhPMN`. The cleanup trap
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

A later activation pass found that the preview confirmation bound only impact
counts rather than the exact alias and queue state, and that the authenticated
apply route committed policy without driving those queues into visible holds.
Preview and apply now hash a length-framed transcript of every enabled alias
identity/target document and every affected queue/recipient identity. Tests
replace an alias and a queue with different same-count state and prove the old
confirmation is rejected. After commit, the product route re-evaluates every
selected queue through the normal transport policy and invokes the verified
whole-message reconciler. Helper failure remains a durable retryable error;
repeating a confirmed same-scope apply retries the hold without implicit
release. The API integration test observes the queue reach `held` through this
real route.

The repaired API pass then found that authorization used the raw domain before
normalization and that incomplete post-commit reconciliation still returned an
ordinary `200`. Requests now canonicalize the domain before resolving the
domain-scoped token. Fully reconciled activation returns `200`; committed
policy with remaining hold failures returns `202 Accepted` and exact selected,
held, already-held, no-longer-blocked, and failed counts. API tests cover both
the DNS-equivalent authorization form and the pending-reconciliation status.
The `202` path sets the JSON media type before committing the status; its API
regression requires both the status and header.

The repaired-tree pass found that unauthenticated inbound queue admission
treated a reverse path matching a hosted mailbox as authoritative local sender
provenance. That trusted spoofable envelope text and could inject an unintended
governing domain into a legitimate forward. Admission now derives sender
authority only from an authenticated mailbox or durable system-sender binding;
unauthenticated inbound mail is governed solely by the local expansion objects
that created the outbound delivery. Focused normal and race suites passed with
a spoofed-local-sender regression test.

The following pass found that the old final-relay proof still depended on a
new unauthenticated local injection and that the reference server's in-memory
forward fixture had drifted from its SQL admission fixture. The gate now maps
only an authenticated `system:` SASL identity to durable system-sender
authority, ordinary SASL identities remain mailbox authority, and ambiguous
dual authority is rejected. The smoke reuses the held inbound forward after
explicit release. Both fixtures now expand it to two external recipients, and
the rebuilt stack proved one final SMTP transaction with both recipients.

The next runtime pass found that signed notification email performed the
correct durable system-sender policy check but used unauthenticated SMTP, so
the final Postfix gate could not recover that authority. The notification
transport now requires CRAM-MD5 authentication with a username exactly equal
to `system:<from-address>` and a bounded direct or private-file secret.
Submission policy and final transport share the same authenticated-identity
classifier. A real Postfix/Cyrus spike proved that a colon-bearing system ID is
stored unchanged as the queue `sasl_username`. The rebuilt reference stack
then proved the restricted identity is rejected at RCPT, and—after an explicit
policy change—the same authenticated identity is admitted at submission,
recorded as system-sender queue provenance, rechecked at final transport, and
accepted in exactly one SMTP transaction.

The subsequent pass found that the automatic-mail classifier still did not
connect Postfix-generated DSNs and bounces to final transport. The reference
Postfix configuration now uses an exact null-sender map and a dedicated pipe
service carrying a fixed durable mailer-daemon identity. Real `postqueue -j`
output exposed that Postfix renders a null sender as `MAILER-DAEMON`; queue
inspection now canonicalizes that documented display to `<>`. Queue admission
accepts `<>` only with an explicit durable system identity, while ordinary
address-bearing identities retain exact envelope binding. Focused normal and
race suites passed, and the rebuilt container stack relayed one null-sender
message only after registering the expected system-sender provenance.

That repair's fresh review found that sender-dependent transport selection was
not itself proof of local generation: an unauthenticated inbound bounce also
uses `MAIL FROM:<>`. Postfix's documented pipe contract exposes the original
`client_address`, so the dedicated transport now passes it to the gate. A
non-empty client address suppresses the fixed system identity and leaves
authority to the proven local expansion objects. The rebuilt stack submitted
an inbound null-sender message over SMTP, held its two-target expansion with
exactly one list source and no system source, explicitly released and relayed
it, then separately proved that locally generated null-sender mail receives
the durable mailer-daemon source.

## Final admission

The committed `ba851a9` tree passed:

- repository-wide serial tests with `go test -p=2 ./... -count=1`;
- repository-wide race tests with `go test -race -p=2 ./... -count=1`;
- `go vet ./...`;
- builds of `gotth-mail`, `gotth-mailctl`, `gotth-mail-plugin`, and
  `gotth-mail-postfix-gate`;
- shell syntax checks, `docker compose config --quiet`, `git diff --check`, and
  a clean worktree;
- a final rebuilt-container smoke covering held inbound forwarding, explicit
  release, one unrestricted two-recipient relay, authenticated system-sender
  submission/final transport, and locally generated null-sender transport.

A fresh final review of submission, transport, helper, and release boundaries
returned clean. An independent second review of persistence, migrations,
backup/restore, queue identity, state transitions, and failure visibility also
returned clean. No live service or production state was changed.
