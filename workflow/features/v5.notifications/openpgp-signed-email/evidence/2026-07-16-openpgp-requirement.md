# OpenPGP signed email requirement evidence

Date/time: 2026-07-16 10:21 CDT

Commit: current commit; hash assigned by Git after commit

## Requirement

Danny required OpenPGP and required every outbound email to be signed.

## Canonicalized behavior

- Every outbound email must be OpenPGP/MIME signed.
- DKIM remains domain/server proof but does not replace per-user OpenPGP signatures.
- Missing, revoked, expired, disabled, mismatched, or failed signing key state blocks send.
- No unsigned fallback is allowed for convenience or alert delivery.
- Signing fingerprint/status/failure reason must be auditable.
- Imported historical mail may remain unsigned, but newly sent, resent, automated, notification, approval, or system-generated outbound mail must be signed before leaving the system.

## Files updated

- `docs/prd/PRD.md`
- `docs/prd/PRD-v4-webmail.md`
- `docs/architecture/v4-webmail.md`
- `docs/implementation/v4-webmail.md`
- `docs/prd/PRD-v5-notifications.md`
- `docs/architecture/v5-notifications.md`
- `docs/implementation/v5-notifications.md`
- `workflow.toml`
- `workflow/COVERAGE.md`
- `workflow.events.jsonl`
- `workflow/features/v5.notifications/openpgp-signed-email/README.md`

## Verification

Required for this docs/spec change:

```text
git diff --check -- .
go test ./...
```
