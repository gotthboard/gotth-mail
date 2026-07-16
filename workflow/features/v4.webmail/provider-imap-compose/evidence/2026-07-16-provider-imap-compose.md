# v4 provider IMAP compose evidence

Feature: `v4.webmail.provider-imap-compose`
Timestamp: 2026-07-16 13:15 CDT

## Scope

Drafted custom webmail provider core seams with external-provider continuity, folder list, message list/read, pagination/windowing, quota display, draft save, submit, reply/forward-capable draft metadata, send failure reporting, and honest SMTP/OpenPGP boundary modeling.

## Verification

- `go test ./internal/webmail` covers external provider continuity, folder list, message list pagination, message read, quota display, draft save, send failure for unsigned mail, and signed submit success.
- `go test ./...` passed before admission.
- `git diff --check -- .` passed before admission.

## Coverage gaps

Admission pending; no accepted coverage gap shall be recorded until cold review passes.
