# Implementation Spec — 2.0 Go-native mail engine

Source PRD: [PRD-release-2.0.md](../prd/PRD-release-2.0.md)
Source architecture: [release-2.0.md](../architecture/release-2.0.md)

## Dependency rule

The canonical 2.0 runtime must not execute, shell out to, generate
configuration for, or require NGINX, Postfix, Dovecot, Pigeonhole, or Rspamd.
Compatibility importers may read their exported state in an isolated migration
job. Test harnesses may run admitted 1.x daemons as external oracles, but those
processes are not 2.0 artifacts.

Go standard-library and reviewed module dependencies are allowed. TLS,
cryptographic signatures, password hashing, Unicode/IDNA, DNS wire handling,
and MIME primitives must use reviewed implementations where available. No
project-local cryptographic primitive is admissible.

## Role contract

One source tree may build `gotth-mail` with compile-time role identity or
separate role commands. Production artifacts must lock one of:

- `edge`;
- `transport`;
- `mailbox`;
- `message-intelligence`;
- `control`;
- `worker`.

Each role has an explicit listener allowlist, filesystem allowlist, capability
set, health/readiness contract, resource budget, and authenticated private API.
The all-in-one profile instantiates the same role services and contracts in one
deployment unit without granting cross-role authority.

## Protocol implementation

### SMTP

Implement bounded SMTP/ESMTP server and client state machines with explicit
extensions, reply classes, command sequencing, line/message limits, AUTH,
STARTTLS, SMTPUTF8/8BITMIME policy, DSN behavior, trace headers, and exact
recipient/envelope state. Durable acknowledgement occurs only after the queue
or local-delivery transaction commits.

### Queue and delivery

Queue records carry immutable message identity, content digest, sender and
recipient sets, policy revision, attempt history, next-attempt time, lease,
delivery ambiguity, and terminal disposition. Workers use bounded leases and
idempotency keys. Crash recovery must distinguish definitely-not-sent,
definitely-sent, and ambiguous attempts; ambiguity never becomes an automatic
blind resend.

### Mailbox, IMAP, and JMAP/API

Define one canonical mailbox model for messages, blobs, mailboxes/folders,
flags, keywords, quotas, change sequences, search indexes, and expunge state.
JMAP/product API and IMAP adapters operate on that model. IMAP command and
response parsing is bounded; concurrent sessions observe ordered durable
changes and cannot resurrect expunged state.

### Message intelligence

Model every SPF, DKIM, DMARC, ARC, MIME, malware-provider, spam, reputation,
rate, and local-policy signal as bounded structured evidence. Verdicts include
the exact policy revision and explanation. Required-check timeout or malformed
evidence follows explicit defer/quarantine/reject policy rather than an
implicit accept.

## Staged delivery

Implementation order is:

1. shared protocol types, canonical message identity, capture/replay corpus,
   and role security scaffolding;
2. Go edge parity and NGINX removal;
3. canonical mailbox/JMAP model, IMAP compatibility, and Dovecot migration;
4. durable SMTP transport/queue and Postfix migration;
5. Go message-intelligence parity and Rspamd removal;
6. full daemon-free deployment, migration, rollback, and beta admission.

No stage removes the admitted 1.x component until the replacement passes
shadow parity, negative tests, load/recovery tests, independent review, and a
rehearsed rollback.

## Verification

- RFC-derived conformance matrices and external interoperability suites for
  SMTP, IMAP, JMAP/API, DNS, TLS, MIME, SPF, DKIM, DMARC, and ARC;
- continuous fuzzing of every public parser and state machine;
- malformed, oversized, slow-client, downgrade, replay, credential, and
  authorization-negative tests;
- race, repeat, shuffle, long-duration, fault-injection, disk-full,
  partial-write, crash/restart, network-partition, and clock-skew tests;
- queue duplicate/loss proofs and mailbox concurrency/integrity proofs;
- exact-sender OpenPGP/MIME and no-unsigned-fallback tests;
- migration manifests comparing identity, mailbox, message, flag, folder,
  quota, queue, key-binding, and audit state before and after cutover;
- live inbound/outbound delivery across independent providers and clients;
- backup, isolated restore, upgrade, downgrade refusal, and rollback drills;
- `go test`, race tests, vet, static analysis, dependency/license review,
  container inspection, `git diff --check`, and independent cold admission.
