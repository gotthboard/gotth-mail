# Architecture — 2.0 Go-native mail engine

Source PRD: [PRD-release-2.0.md](../prd/PRD-release-2.0.md)

## Architectural rule

GOTTH Mail 2.0 is one Go codebase and one release, not one undifferentiated
process. The same source tree may produce one role-aware binary, but each
production artifact has a fixed role, least-privilege identity, listener set,
mount set, health contract, and state authority. Runtime flags cannot turn a
public edge process into a control-plane or storage process.

The canonical production topology contains no NGINX, Postfix, Dovecot,
Pigeonhole, or Rspamd process.

## Roles

### Edge

The edge owns public SMTP/IMAP listeners, TLS/STARTTLS, bounded parsing,
connection policy, authentication exchange, and provenance. It performs no
mailbox mutation and owns no durable queue. It calls only versioned private
transport, mailbox-authentication, and policy contracts.

### Transport

The transport role owns SMTP state machines, routing, local-delivery
handoff, outbound delivery, durable queues, retry scheduling, DSNs, and final
transport policy. Queue state is transactional and every attempt is
idempotently correlated to the canonical message and policy revision.

### Mailbox and API

The mailbox role owns message/blob placement, folders, flags, quotas, search
indexes, change sequences, IMAP state, and JMAP/product API state. Webmail uses
the native API. IMAP is a compatibility surface over the same canonical
mailbox model, not a second store.

### Message intelligence

The message-intelligence role owns MIME limits, spam/abuse signals, SPF/DKIM/
DMARC/ARC evaluation, signing decisions, and explainable verdicts. It cannot
silently override transport, exact-sender, or authorization policy.

### Control plane

The control plane retains typed configuration, identities, authorization,
audit, domain/mailbox policy, extension administration, deployment intent,
backup metadata, and operator interfaces. Authentik remains an adjacent OIDC/
SCIM provider; provider outage cannot stop established mail delivery.

### Workers

Workers perform bounded indexing, retention, notification, backup, restore,
certificate, and migration jobs. Jobs are durable, leased, idempotent, and
audited. Worker credentials do not grant edge, queue, or mailbox authority.

## State and trust boundaries

- Queue, mailbox, identity/policy, audit, and blob state have explicit owners.
- Role calls use authenticated, versioned contracts with deadlines,
  correlation IDs, bounded payloads, and structured errors.
- Secret material is file- or provider-backed and never enters image labels,
  command arguments, logs, or release manifests.
- Public protocol parsers are memory- and time-bounded and fuzzed continuously.
- A supported all-in-one deployment keeps the same contracts and authority
  checks in-process; it is packaging, not a bypass architecture.

## Migration architecture

Replacement proceeds by boundary, not by a flag-day rewrite:

1. Go edge shadows and then replaces NGINX while Postfix/Dovecot remain the
   admitted private backends.
2. Go mailbox/JMAP state is admitted, followed by IMAP compatibility and a
   controlled Dovecot migration.
3. Go transport and durable queue shadow Postfix decisions, then take over
   submission, local delivery, and outbound relay under exact replay guards.
4. Go message intelligence reaches parity and replaces the Rspamd boundary.
5. The daemon-free topology runs the complete beta and rollback matrix.

Shadow components receive redacted or protected production-shaped inputs and
cannot deliver mail, emit DSNs, mutate mailboxes, or advance queue state.

## Failure boundaries

- Edge failure stops new connections without corrupting queue or mailbox
  state.
- Transport failure preserves durable queue ownership and never duplicates a
  previously acknowledged delivery.
- Mailbox failure cannot acknowledge a local delivery before durable commit.
- Message-intelligence uncertainty defers or quarantines according to explicit
  policy; it never silently permits a required check.
- Control-plane or identity-provider outage blocks new administrative or login
  actions but does not invalidate established mail-runtime state.
- Rollback never attaches two active writers to one queue or mailbox lineage.
