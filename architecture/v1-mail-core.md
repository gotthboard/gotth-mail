# Architecture — v1 Mail Core

Source PRD: [PRD-v1-mail-core.md](../PRD-v1-mail-core.md)

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
- plugin containers pass health/capability checks
