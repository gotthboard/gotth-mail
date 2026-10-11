# GOTTH Mail PRD — v1 Mail Core

## Goal

v1 makes GOTTH Mail a real mail-server control plane. It must provide the Postfix, Dovecot, and Rspamd contracts, generate DNS/TLS guidance, run diagnostics, prove mail flow through smoke tests, and ship the first mechanism-plugin containers needed for a working deployment.

## Scope

### v1.1 Postfix contracts

- Domain lookup.
- Recipient lookup.
- Mailbox lookup.
- Alias expansion.
- Sender login authorization.
- Sender policy.
- Sender rate limits.
- Transport lookup.
- Contract tests for happy paths and failure paths.

### High-priority per-domain outbound scope

- Each hosted domain has an explicit `outbound_scope` value:
  `unrestricted` or `same_domain_only`.
- `unrestricted` remains the default for existing and newly created domains;
  restriction requires an administrator's explicit preview and confirmation.
- `same_domain_only` permits a mailbox or system identity in that domain to
  send only to the exact canonical domain. Subdomains and other domains hosted
  by the same GOTTH Mail installation are external for this decision.
- The governing domain set includes the authenticated mailbox, admitted
  envelope sender, system-sender identity, and every local alias, forward, or
  list that originates another delivery. A restricted domain cannot be escaped
  by sending as an address in another domain or by forwarding inbound mail.
- The restriction applies to SMTP envelope recipients, not message headers,
  and covers authenticated SMTP, webmail/API submission, aliases, forwards,
  lists, BCC recipients, catch-alls, notifications, autoresponders, DSNs,
  bounces, retries, queue replay, and final Postfix handoff.
- Alias and forwarding expansion must be evaluated before a recipient is
  admitted. No indirection may turn an allowed local recipient into an
  external delivery. Queue-time provenance cannot treat an unchanged
  original/final address as terminal when the authoritative alias graph already
  proves that original is an alias, catch-all expansion, or self-cycle root.
- Incoming mailbox delivery remains independent: enabling the restriction does
  not prevent the domain from receiving mail from external domains. Any later
  forwarding or autoresponse is a new outbound action and is restricted.
- SMTP submission rejects each forbidden recipient at `RCPT TO` with
  `550 5.7.1`. Webmail and API submission reject the complete request before
  queueing when any resolved recipient is forbidden.
- Before the final queue becomes deliverable, bind its immutable complete
  original final-envelope recipient set and authoritative expansion provenance
  to that queue ID. A delivery request batch and a concurrent queue scan are not
  recipient authority. Every final delivery attempt, including native retry
  after a remote temporary failure, rechecks the full bound set against current
  policy. Enabling the restriction must preview affected aliases, forwards, and
  queued recipients. If any bound recipient is forbidden, durable hold_required
  prevents the current and every later batch from reaching the network while the
  whole original queue message enters visible policy hold. No held message is
  silently deleted or automatically replayed.
- Every preview, activation, rollback, rejection, deferral, and blocked queued
  disposition is audited without recording message bodies or secrets.

### v1.2 Dovecot contracts

- passdb lookup.
- userdb lookup.
- quota updates.
- app-password auth path.
- mailbox identity mapping.
- default sieve data where needed.
- Contract tests for happy paths and failure paths.

### v1.3 Rspamd contracts

- Local-domain list.
- DKIM key lookup.
- Spam/rate-limit signal surface.
- DKIM signing path.
- Contract tests for DKIM/local-domain behavior.

### v1.4 DNS + TLS

- DNS guidance for:
  - MX
  - SPF
  - DKIM
  - DMARC
  - DMARC report records
  - SRV/autoconfig/autodiscover
  - TLSA where applicable
- DNS readiness score per domain.
- TLS validation.
- Let’s Encrypt issuance/renewal.
- ACME challenge path through the front service.
- Cert expiry and SAN checks.
- MTA-STS policy generation and serving.
- TLS-RPT DNS/config guidance.
- Renewal audit events.

### v1.5 First plugin containers

First mechanism-plugin implementations required for a working deployment:

- selected webmail provider container/config integration
- manual/export DNS provider plugin container
- Let’s Encrypt/manual cert plugin container
- local filesystem backup storage plugin container

Each plugin container must:

- use gRPC/protobuf
- expose health/version/capability RPCs
- authenticate with service identity credentials
- use deadlines and structured errors
- avoid broad filesystem mounts
- avoid Docker socket access

### v1.6 Diagnostics

- `gotth-mail doctor` for:
  - DNS
  - ports
  - TLS/certificates
  - DKIM
  - database
  - Authentik reachability
  - selected webmail provider reachability
  - generated config
  - daemon lookup health
  - plugin health
- Daemon lookup debugger for:
  - recipient decisions
  - sender decisions
  - alias expansion
  - domain matching
  - Dovecot auth/userdb
  - Rspamd DKIM/local-domain answers
- Mail flow trace:
  - recipient lookup
  - alias expansion
  - transport decision
  - spam/DKIM path
  - delivery mailbox
- Queue visibility:
  - Postfix queue summary
  - deferred reasons
  - retry/flush controls with audit
- Machine-readable diagnostics.

### v1.7 Smoke tests + snapshots

- Safe mail smoke test:
  - SMTP submission
  - receive path
  - alias delivery
  - IMAP login
  - DKIM signing
  - delivered smoke mail visible through the selected webmail provider
- Known-good snapshot capture for:
  - generated config
  - image versions
  - migration version
  - plugin image/version
  - selected deployment policy

### v1.8 Mail admin UI

- Domain CRUD.
- User CRUD.
- Alias CRUD.
- DNS/DKIM screens.
- Doctor screens.
- Lookup debugger UI.
- Plugin status/config screens.
- All mutations go through service/auth/audit paths.

## Non-goals

- No custom webmail client.
- No SCIM provisioning implementation unless it is needed only for fixtures.
- No notification approval workflow.
- No Mailu import.

## Acceptance criteria

- Postfix, Dovecot, and Rspamd can run against GOTTH Mail internal APIs.
- Contract tests cover daemon lookup happy paths and failure paths.
- Generated config can be rendered, diffed, applied, and audited.
- DNS readiness reports exact missing/mismatched records.
- Let’s Encrypt issuance/renewal works in the reference deployment or fails loudly with actionable doctor output.
- MTA-STS policy serving and TLS-RPT guidance are generated and doctor-checked when enabled.
- Smoke test proves SMTP submission, receive, alias delivery, IMAP login, DKIM signing, and delivered smoke mail visibility through the selected webmail provider.
- Plugin containers are wired through Compose and pass gRPC health/capability checks.
- Mail delivery and daemon lookups do not depend on Authentik availability.
- A `same_domain_only` domain cannot produce an external delivery through any
  supported submission, expansion, automatic-message, retry, or replay path.
- Policy-store or decision-service failure defers mail; it never falls back to
  unrestricted delivery.

## Exact-sender outbound forwarding (release 1.0)

FWD-1: Owner decision 2026-09-26 15:33 CDT: unsigned remote mail automatically
forwarded externally becomes a NEW message signed by an explicitly configured
local forwarding identity. Attach the untouched captured original; never assert
that the local identity authored it. Visible From/reply/thread changes are
intentional. Ordinary local inbound delivery stays unchanged.

FWD-2: The bounded construction component emits one original.eml attachment,
application/octet-stream with base64 transfer encoding, a fixed explanatory
body/subject, local From and Reply-To, a new caller-owned Date/Message-ID, and
no inherited remote author, recipients, or threading. Only resolved, signed and
cryptographically verified output may be returned; failures return no message.

FWD-3: Caller-provided identity must already be authorized for this forwarding
context. Key possession, MIME headers and successful verification do not grant
that authority. Missing/ambiguous/inactive/unusable signing state fails closed.
This component alone does not enforce all outbound paths or authorize delivery.

FWD-4: Capture is the exact byte slice supplied by the trusted caller, not a
claim about pre-queue SMTP bytes. Component size limits must account for base64
and existing MIME parser/verifier bounds without reducing current inbound or
submission limits. Full-size forwarding, queue ownership/provenance, audit,
expiry/bounce handling and final retry enforcement remain release requirements.
Encoded MIME parts and their decoded payloads are bounded independently; a
valid encoded prefix at the limit must not be accepted as a successful truncated
part when more encoded data exists.

FWD-5: The signed-forwarding component accepts at most 52,428,800 captured
original octets and may emit at most 72,796,392 signed replacement bytes. This
is a private component capacity, not a claim that public Postfix accepts an
SMTP DATA body of that size. The 25MiB hostile-display parser cap remains
independent.

FWD-6: Final outbound body custody remains with one bound Postfix queue, not
a second queue created after policy admission. A thin delivery-agent gate checks
current policy for each qmgr delivery request before any external DNS/connect and
delegates an allowed request to stock Postfix smtp without reinjection. If policy
or identity state is unavailable, delivery defers. If policy now forbids an
authoritatively bound recipient, delivery tempfails while a privileged reconciler
places the original queue message on visible policy hold; release rechecks policy.
A remote 4xx retry must re-enter the gate and cannot bypass that fresh check.

FWD-7: For a non-null forwarded delivery, the configured local forwarding
identity is the SMTP envelope sender and local DSN destination. The remote
original author is never used as MAIL FROM or as DSN authority. If the triggering
automatic delivery has a null envelope sender, the forwarded delivery remains
null and bounce-suppressed; it does not manufacture a local or remote bounce.
