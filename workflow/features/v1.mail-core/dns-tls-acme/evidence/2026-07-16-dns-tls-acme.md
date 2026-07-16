# v1 DNS/TLS/ACME evidence

Date/time: 2026-07-16 01:45 CDT

Commit: 6b8fa6603a0e47580dbc3c6996c6f9a8397aec2b

## Scope implemented

Implemented only `v1.mail-core.dns-tls-acme` diagnostics/generation primitives.

Added `internal/diag` coverage for:

- exact DNS readiness status values: `present`, `missing`, `mismatch`, `not_checked`, `unsupported`
- MX, SPF, DKIM, DMARC, SRV/autoconfig/autodiscover, MTA-STS, TLS-RPT, and TLSA checks
- expected value, observed value, status, and remediation text per DNS record
- TLS certificate PEM parsing, expiry warning/failure, and required SAN validation
- MTA-STS policy generation
- TLS-RPT record generation
- loud/actionable ACME failure result construction

## Verification performed

Passed:

```text
go test ./...
```

Covered behavior:

- DNS present/missing/mismatch/unsupported statuses
- exact remediation text includes expected and observed values
- TLSA disabled reports unsupported rather than fake success
- certificate SAN mismatch fails
- certificate expiring soon warns
- expired certificate fails
- MTA-STS and TLS-RPT generation are deterministic
- ACME failure returns `ok=false`, stable error code, and actionable message

## Known gaps / next increments

Still outside this child:

- live DNS resolver integration and network timeout handling
- real ACME issuance/renewal plugin execution
- doctor API/CLI aggregation
- reference Compose mail-flow smoke

No accepted gap remains inside the pure DNS/TLS/ACME diagnostic primitive surface implemented here.

## Next recommendation

Proceed to `v1.mail-core.first-plugins`: add first mechanism plugin containers/protobuf seams for webmail, DNS export, cert/manual-ACME, and local backup, all using v0 plugin control authentication.
