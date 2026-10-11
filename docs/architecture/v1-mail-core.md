# Architecture — v1 Mail Core

Source PRD: [PRD-v1-mail-core.md](../prd/PRD-v1-mail-core.md)

## Goal

v1 makes the system a real mail control plane by implementing explicit contracts for Postfix, Dovecot, and Rspamd, plus DNS/TLS generation, doctor, lookup debugging, smoke tests, snapshots, and first mechanism-plugin containers.

## Runtime topology

Adds or hardens:

- front/proxy container
- Postfix container
- Dovecot container
- Rspamd container
- selected webmail provider container
- DNS provider plugin container, manual/export first
- ACME/certificate plugin container, manual + Let's Encrypt
- backup storage plugin container, local filesystem first

Mail delivery and daemon lookup paths must not depend on Authentik availability.

## Internal daemon API architecture

Internal daemon APIs are core contracts, not plugin seams.

### Postfix contract group

Responsibilities:

- domain lookup
- recipient lookup
- mailbox lookup
- alias expansion
- sender login authorization
- sender policy
- sender rate limits
- transport lookup

Failure behavior must be explicit: reject, defer, not-found, or error. Do not hide lookup failure behind fake success.

### Per-domain outbound policy boundary

The control-plane database is authoritative for a domain's outbound scope.
`unrestricted` is the compatibility default; `same_domain_only` is an explicit,
audited domain policy. The comparison uses normalized SMTP envelope domains:
lowercase ASCII A-label form with a single terminal dot removed. Equality is
exact. A subdomain or another hosted domain is not treated as local to the
sender's policy domain.

The control plane derives a governing policy-domain set from authoritative
local objects: the authenticated mailbox, admitted envelope sender,
system-sender binding, and each alias/list/forward/catch-all source that creates
another delivery. A caller-supplied `From` header never supplies or removes a
domain. Each `same_domain_only` member of the set must equal the recipient
domain. If distinct restricted domains govern one action, no recipient can
satisfy both and the action is rejected as a cross-domain authorization
conflict. This prevents delegated send-as and chained forwarding from becoming
bypasses.

Postfix asks the control plane at `RCPT TO`, after each expansion, and again at
the final transport boundary. Queue entries retain the originating policy-
domain set but are checked against every current policy revision on retry and
replay. The final Postfix queue remains sole body custodian. Before it becomes
deliverable, immutable original final-envelope recipients and authoritative
expansion provenance are bound to its queue ID. The active DELIVER_REQUEST batch
is not that authority, and no racy queue scan may replace it. For each qmgr
delivery request, a thin delivery-agent gate asks a fail-closed broker to evaluate
the full bound set before any external DNS/connect, and on allow delegates the
same request through Postfix deliver_pass to stock smtp. It does not perform
SMTP or reinject. On forbiddance it durably records hold_required and tempfails; every later batch
for that queue is denied before network while a privileged reconciler holds and
verifies the original queue after the request returns. Release rechecks policy. A second Postfix queue created after
admission is not an authorization boundary: executable RED evidence showed
native retry of that second queue can deliver after revocation without a fresh
policy call. Queue admission may fast-path a truly direct unchanged original/final recipient only
after the already-loaded expansion map shows that the original is not an
authoritative alias or catch-all root; an equal self-cycle or root alias fails
before queue registration.

Authenticated SMTP preserves SMTP's per-recipient behavior: each forbidden
recipient receives `550 5.7.1`, while separately admitted recipients may
proceed. Webmail and product APIs use atomic submission and reject the whole
request before queueing if any fully resolved recipient is forbidden. Incoming
mailbox delivery remains a separate path and is not rejected merely because the
recipient domain restricts outbound delivery. A forward, autoresponse, or other
new outbound action triggered by that message adds its authoritative local
source domain and crosses the outbound boundary normally.

Automatic mail, including notifications, autoresponders, DSNs, and bounces,
inherits the originating domain identity in durable queue metadata and crosses
the same policy boundary. For non-null signed forwarding, the configured local
forwarding identity is the SMTP envelope sender and local DSN destination; the
remote original author is never envelope or DSN authority. A null-sender trigger
stays null and bounce-suppressed. A restricted domain must not accept mail and later
create an external DSN when an SMTP-time rejection was possible. When no safe
SMTP-time rejection exists, the automatic external message is suppressed,
given a safe terminal policy disposition, and audited without message content.

Enabling the restriction is a preview/confirm transaction bound to the current
domain-policy revision and a digest of affected aliases, forwards, and queued
recipient records. Activation increments the revision. Queued external
recipients cause their whole Postfix queue message to enter a visible
product-owned policy hold because Postfix does not provide honest per-recipient
hold semantics. This can delay otherwise permitted recipients on that message;
the preview must say so. Held messages are neither delivered nor silently
deleted. Returning to `unrestricted` is a separate explicit audited operation
and does not automatically release held mail.

Policy activation and Postfix hold application cannot be one database
transaction. The database policy becomes authoritative first, so the final
transport recheck defers any racing external delivery. The reconciler then
places every affected queue ID on hold idempotently and records success or a
retryable reconciliation error. Failure to apply a hold may delay mail through
temporary deferral; it must never permit the external delivery.

Queue control uses Postfix's documented whole-message hold/release operations
through a narrow privileged helper. The control plane passes one validated long
queue ID as an argument, never a shell command or arbitrary queue selector.
Long queue IDs are required, and the reconciler verifies queue metadata before
and after the hold to reduce queue-ID reuse races. The helper exposes no delete,
expire, requeue-all, or unrestricted command surface.

Policy uncertainty fails closed for delivery: an unavailable database or
decision service produces a temporary `451` deferral. There is no permissive
cache fallback, trusted internal sender bypass, cross-hosted-domain exception,
or header-based escape hatch.

### Dovecot contract group

Responsibilities:

- passdb lookup
- userdb lookup
- quota updates
- app-password auth path
- mailbox identity mapping
- default sieve data where needed

Dovecot auth must use app-password/mail-client token primitives honestly. OIDC is not an IMAP/SMTP auth protocol.

### Rspamd contract group

Responsibilities:

- local domain list
- DKIM key lookup
- spam/rate-limit signal surface
- DKIM signing path

DKIM private key access must be least privilege and auditable at the control-plane boundary.

## Generated daemon config

The render/apply gate from v0 generates daemon config for:

- front/proxy
- Postfix maps/config
- Dovecot auth/userdb/quota config
- Rspamd local-domain/DKIM config
- selected webmail provider

Generated config remains reproducible from typed config + database state + selected deployment policy.

## DNS and TLS architecture

DNS guidance includes:

- MX
- SPF
- DKIM
- DMARC
- DMARC report records
- SRV/autoconfig/autodiscover
- TLSA where applicable

TLS architecture includes:

- manual certificates
- Let's Encrypt issuance/renewal
- ACME challenge path through front service
- cert expiry checks
- SAN coverage checks
- renewal audit events

MTA-STS and TLS-RPT are generated and doctor-checked when enabled.

## Plugin containers in v1

First plugin containers:

- webmail provider integration
- DNS manual/export provider
- ACME/certificate provider
- local backup storage provider

Every plugin uses:

- gRPC/protobuf
- service identity credentials
- health/version/capability RPCs
- deadlines and structured errors
- no Docker socket
- no broad filesystem mounts

Core still owns policy and state admission.

## Diagnostics architecture

### Doctor

Doctor checks:

- DNS
- ports
- TLS/certs
- DKIM
- database
- Authentik reachability
- selected webmail reachability
- generated config
- daemon lookup health
- plugin health

Doctor output must distinguish config errors, DNS/TLS external state, daemon reachability, identity-provider issues, and plugin failures.

### Lookup debugger

Explains:

- recipient decisions
- sender decisions
- alias expansion
- domain matching
- Dovecot auth/userdb
- Rspamd DKIM/local-domain answers

### Mail flow trace

Traces:

- recipient lookup
- alias expansion
- transport decision
- spam/DKIM path
- delivery mailbox

### Queue visibility

Provides:

- Postfix queue summary
- deferred reasons
- retry/flush controls with audit

## Smoke test architecture

Safe smoke test proves:

- SMTP submission
- receive path
- alias delivery
- IMAP login
- DKIM signing
- delivered smoke mail visible through selected webmail provider

Smoke tests must clean up or report created artifacts.

## Snapshot architecture

Snapshots capture:

- generated config
- image versions
- migration version
- plugin image/version
- selected deployment policy

Snapshots are reference points, not rollback guarantees unless paired with verified backups.

## Verification gates

- Postfix/Dovecot/Rspamd contract tests pass for happy and failure paths
- generated config renders/diffs/applies/audits
- DNS readiness identifies exact missing/mismatched records
- Let's Encrypt works or fails loudly with doctor output
- MTA-STS/TLS-RPT generated and checked when enabled
- smoke test passes including webmail visibility
- plugin containers pass authenticated gRPC health/capability checks
- mail delivery and daemon lookup smoke/contract checks pass with Authentik unavailable or isolated

## Exact-sender outbound forwarding (release 1.0)

FWD-1..4 use a bounded webmail MIME construction component composed with the
existing SenderIdentityResolver, OpenPGPSigner and ExactSenderVerifier. Core
retains context authorization and authoritative expansion-to-identity mapping.
The component has no SMTP, queue, policy-mutation or identity-enrollment side
effects. It returns only verified bytes and signature status, never unsigned
intermediates. Local inbound LMTP remains outside this transformation.

The original is opaque base64 data, not reparsed or normalized. RFC 2046 §5.2.1
forbids base64 on message/rfc822, hence application/octet-stream/original.eml.
Outer MIME follows RFC 3156 §§3/5: seven-bit bytes, CRLF and no trailing
whitespace; the existing OpenPGP implementation owns detached signing, packet
hash checks, authoritative header binding and raw-entity verification. Existing
BuildMIME attachments are raw and lack transfer-encoding; changing all compose
callers is unnecessary. Use standard MIME/base64 construction for this distinct
opaque attachment while reusing identity/header validation and crypto APIs.
The inbound/parser side enforces the same part ceiling on both encoded octets
and decoded octets. Decoder EOF after an encoded cap sentinel is not trusted as
whole-part EOF; oversize encoded data fails instead of returning a valid prefix.

Gate.Deliver before final remote DATA is the intended integration point, NOT
wired by this component slice. Durable provenance/context admission,
original/local and external queue ownership, stable artifacts, failure
disposition and retry policy must precede that integration. Do not infer a
system author from null MAIL FROM, remote From or a queue ID. The old
private-10027/content-filter shape is RED-proven insufficient for current-policy
retry enforcement because queue B is owned by stock smtp without another policy
call; do not call this global enforcement or beta completion.

Full-size component capacity is private to SignedForwardBuilder: captured
original bytes are capped at 50MiB (52,428,800 octets), while the signed wrapper
has its own 72,796,392-byte ceiling. Public SMTP/Postfix limits, queue custody,
retry and Gate concurrency stay outside this component. The parser's 25MiB
display limit is intentionally not relaxed; forwarding tests recover the opaque
original from the signed MIME without using the hostile-display parser.
