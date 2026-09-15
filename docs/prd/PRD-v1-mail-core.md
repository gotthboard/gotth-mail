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
  external delivery.
- Incoming mailbox delivery remains independent: enabling the restriction does
  not prevent the domain from receiving mail from external domains. Any later
  forwarding or autoresponse is a new outbound action and is restricted.
- SMTP submission rejects each forbidden recipient at `RCPT TO` with
  `550 5.7.1`. Webmail and API submission reject the complete request before
  queueing when any resolved recipient is forbidden.
- Delivery rechecks the current domain policy. Enabling the restriction must
  preview affected aliases, forwards, and queued recipients; confirmed
  activation prevents already-queued external recipients from being delivered.
  If any remaining recipient is forbidden, the whole Postfix queue message is
  placed on a visible policy hold rather than pretending Postfix can hold only
  one recipient. No held message is silently deleted or automatically replayed.
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
