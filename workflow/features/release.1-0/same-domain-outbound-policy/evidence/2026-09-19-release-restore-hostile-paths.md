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
8. submitted a new unrestricted external message through the final transport
   gate into a real SMTP capture socket.

The final disposable held queue ID was `4hnBbb64dmzdnl3`. The cleanup trap
removed the entire Compose project and its volumes.

## Verification completed in this checkpoint

- focused development-host PostgreSQL suites for changed packages and commands;
- container build's repository-wide test run;
- two successful outbound-policy container smokes, including the final expanded
  inbound-forward and allowed-relay version;
- shell syntax checks for the smoke and SMTP sink;
- local focused tests and `git diff --check`.

## Remaining admission work

- repository-wide serial, race, vet, command-build, Compose-render, and workflow
  traceability gates on the final tree;
- one cold Judge pass, repair of any real finding, then two independent fresh
  clean passes as required by the feature handoff discipline.
