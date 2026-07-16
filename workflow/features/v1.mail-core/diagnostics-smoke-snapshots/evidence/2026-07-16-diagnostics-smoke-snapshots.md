# v1 diagnostics, smoke, and snapshots evidence

Date/time: 2026-07-16 01:56 CDT

Commit: f7f8162c93dac3f7ddc024c135936d553db09fbc

## Scope implemented

Implemented `v1.mail-core.diagnostics-smoke-snapshots` application surfaces:

- doctor aggregation model with `ok`, `warn`, `fail`, `unknown`
- machine-readable checks for config, database, Authentik, webmail, DNS, TLS, daemon lookup path, and plugin health
- lookup debugger model for recipient, sender, Dovecot, and Rspamd-domain lookups
- mail-flow trace model with recipient lookup, alias expansion, transport, spam/DKIM, and delivery mailbox phases
- queue summary/deferred surfaces
- queue flush/retry mutation helpers requiring explicit confirmation and writing audit events
- smoke result model that records webmail visibility, created artifacts, cleanup status, and failure explanation
- snapshot capture model for generated config set, image versions, migration version, plugin versions, deployment policy hash, and timestamp
- explicit `IsRollback=false` snapshot semantics
- API routes for doctor, debug lookup, queue summary/deferred/flush/retry

## Verification performed

Passed:

```text
go test ./...
```

Covered behavior:

- doctor aggregates fail/warn/ok checks
- lookup debugger returns machine-readable steps
- mail-flow trace returns the expected phase sequence
- queue flush/retry reject missing/wrong confirmation
- queue flush/retry write audit events
- snapshots are not represented as rollback
- API routes for doctor/debug/queue surfaces are wired

## Root-level gap

The v1 root is **not done** yet. This child adds smoke-test data modeling, not a proven live reference Compose mail-flow smoke.

Still required before v1 root admission:

- reference Compose includes/runs actual front, Postfix, Dovecot, and Rspamd services against the generated config
- SMTP submission smoke
- receive path smoke
- alias delivery smoke
- IMAP login smoke
- DKIM signing smoke
- selected webmail visibility smoke

No accepted gap remains inside the diagnostics/snapshot/queue/debug API surface implemented here. The remaining gap is the root-level live mail-flow smoke and daemon runtime integration.

## Next recommendation

Do not open v1 as an admission PR yet. Run a cold root review and either implement the missing real daemon/reference Compose integration or explicitly split the root because the current branch proves control-plane contracts, not a working mail-server deployment.
