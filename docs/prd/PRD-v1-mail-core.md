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
