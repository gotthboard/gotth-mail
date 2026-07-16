# v1 daemon contracts evidence

Date/time: 2026-07-16 01:37 CDT

Commit: 824faf10b78352124887aa654bac3f8518ae59fe

## Scope implemented

Implemented only `v1.mail-core.daemon-contracts`.

Added:

- `internal/daemon` service model for Postfix, Dovecot, and Rspamd internal contracts.
- Explicit daemon decision enum: `ok`, `not_found`, `reject`, `defer`, `error`.
- Safe response envelope with correlation ID, reason code, and diagnostic message.
- Postfix contract behavior for:
  - domain lookup
  - recipient lookup
  - mailbox lookup
  - alias expansion
  - sender login authorization
  - sender policy
  - sender rate limit
  - transport lookup
- Dovecot contract behavior for:
  - passdb
  - userdb
  - quota
  - default sieve availability
- Rspamd contract behavior for:
  - local-domain list
  - DKIM key lookup by runtime key path, not private key material
  - signing decision
  - rate signal
- Django/Authenik-compatible `pbkdf2_sha256$iterations$salt$hash` verifier check for Dovecot passdb.
- OIDC-token rejection for IMAP/SMTP passdb.
- HTTP route registration for all required `/internal/v1/postfix/*`, `/internal/v1/dovecot/*`, and `/internal/v1/rspamd/*` endpoints.
- Integration of daemon routes into the main API handler.

## Verification performed

Passed:

```text
go test ./...
```

Covered behavior:

- Postfix happy paths for domain, recipient, mailbox, alias, sender-login, and transport.
- Postfix failure paths for disabled domains, missing recipients, sender mismatch, rate limit rejection, and database-unavailable defer.
- Dovecot passdb success using Django PBKDF2-SHA256 verifier.
- Dovecot passdb rejection for wrong secret, OIDC token, disabled mailbox, and unsupported verifier formats.
- Dovecot userdb and quota success paths.
- Rspamd local-domain, DKIM, signing decision, and missing-domain paths.
- HTTP route method gates, malformed JSON behavior, correlation ID propagation, and JSON decision envelopes.
- API handler wiring for internal daemon routes.

## Known gaps / next increments

These are outside `daemon-contracts` and remain for later v1 children:

- daemon-native Postfix/Dovecot/Rspamd adapter config generation (`v1.mail-core.generated-config`)
- DNS/TLS/ACME checks (`v1.mail-core.dns-tls-acme`)
- first plugin containers (`v1.mail-core.first-plugins`)
- doctor/debug/trace/queue/smoke/snapshot coverage (`v1.mail-core.diagnostics-smoke-snapshots`)
- reference Compose end-to-end mail flow smoke

No accepted gap remains inside the daemon HTTP/JSON decision contract surface implemented here.

## Next recommendation

Proceed to `v1.mail-core.generated-config`: render deterministic Postfix/Dovecot/Rspamd/front config that points daemon-native mechanisms at these internal HTTP/JSON decision contracts, then prove render/diff/apply/audit behavior.
