# GOTTH Mail PRD — 2.0 Go-native mail engine

## Goal

GOTTH Mail 2.0 is a self-contained Go mail platform. Its canonical production
path has no runtime dependency on NGINX, Postfix, Dovecot, or Rspamd. GOTTH
Mail owns the public mail edge, SMTP transport and queue, mailbox protocols and
storage behavior, message intelligence, policy, administration, recovery, and
observability.

This is a new mail-server engine, not a routine refactor of the 1.x control
plane. The historical `v2.identity-provisioning` workflow ID remains a 1.0
capability name and is unrelated to the 2.0 product release.

## Product shape

- one Go codebase and one versioned release;
- role-locked Go artifacts for edge, transport, mailbox/API,
  message-intelligence, control-plane, and background workers;
- a supported all-in-one profile for small installations without collapsing
  the role authorities or bypassing their contracts;
- no external mail daemon in the canonical data path;
- adjacent identity, DNS, certificate, object-storage, and database providers
  remain explicit integrations rather than being silently embedded;
- no bespoke cryptography: use reviewed Go cryptographic and protocol
  libraries where they satisfy the required contract.

## Required capabilities

### Go-native public edge

- SMTP on ports 25, 465, and 587 and IMAP on ports 143 and 993;
- implicit TLS and STARTTLS with strict downgrade behavior;
- bounded protocol parsing, connection limits, timeouts, and abuse controls;
- authenticated submission and private backend routing without NGINX;
- exact client provenance across every internal hop.

### Go-native transport

- inbound SMTP, authenticated submission, outbound relay, local delivery, and
  explicit routing;
- a durable queue with retry schedules, DSNs, dead-letter/operator actions,
  crash recovery, idempotency, and replay-safe policy evaluation;
- DNS resolution, MX handling, TLS policy, MTA-STS, TLS-RPT, SPF, DKIM, DMARC,
  ARC, rate controls, and reputation-safe behavior;
- mandatory exact-sender OpenPGP/MIME signing with no unsigned fallback;
- no Postfix process, configuration, queue, map, policy socket, or helper in
  the canonical 2.0 path.

### Go-native mailbox engine

- durable mailbox/message/blob storage with transactional metadata;
- IMAP interoperability for existing clients and a first-class JMAP/API path
  for GOTTH Mail webmail;
- stable identifiers, flags, folders, quotas, search, rules, concurrency,
  expunge semantics, and restart-safe change tracking;
- app-password authentication, authorization, and audit through canonical
  GOTTH Mail state;
- no Dovecot or Pigeonhole process, passdb/userdb, index, or Sieve runtime in
  the canonical 2.0 path.

### Go-native message intelligence

- MIME validation, content limits, spam and abuse scoring, allow/deny policy,
  DKIM signing/verification, antivirus integration boundaries, and operator
  diagnostics;
- deterministic policy inputs and explainable decisions;
- no Rspamd worker, controller, milter, or configuration in the canonical 2.0
  path.

## Compatibility and migration

GOTTH Mail 1.x is the executable compatibility oracle and rollback boundary.
Each 2.0 role must first run in capture/replay or shadow mode against admitted
1.x traffic and state. Shadow mode may compare decisions and outputs but must
not create duplicate delivery, mutate production mailboxes, emit DSNs, or send
network mail.

Migration must preserve domains, identities, aliases, mailboxes, stable
message identity where representable, flags, folders, quotas, app-password
state, signing-key bindings, queue disposition, audit history, and backup
lineage. Every cutover has a rehearsed stop point, integrity manifest, backup,
rollback artifact, and explicit operator confirmation.

## Non-goals

- inventing cryptographic primitives;
- dropping SMTP or IMAP interoperability to simplify implementation;
- combining all authorities into one privileged process;
- treating a green unit suite as Internet-mail interoperability proof;
- changing 1.x runtime dependencies before a 2.0 replacement is admitted;
- embedding Authentik or granting OIDC claims direct mail authority.

## Acceptance

2.0 beta requires:

1. all canonical mail traffic runs through Go-native roles with NGINX,
   Postfix, Dovecot, and Rspamd absent;
2. protocol conformance, fuzzing, malformed-input, interoperability, load,
   long-duration, and hostile-network suites pass;
3. queue crash/restart/replay and mailbox concurrency/recovery evidence passes;
4. live inbound, outbound, submission, IMAP, JMAP/API, webmail, identity,
   spam-policy, signing, backup, restore, upgrade, and rollback evidence passes;
5. 1.x-to-2.0 migration and rollback are rehearsed against production-shaped
   data with exact integrity manifests; and
6. security review and explicit owner acceptance are complete.

Stable 2.0 additionally requires an operational soak period with no unresolved
delivery-integrity, data-loss, authentication, downgrade, or rollback defect.
