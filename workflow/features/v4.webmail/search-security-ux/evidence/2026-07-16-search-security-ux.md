# v4 search security UX evidence

Feature: `v4.webmail.search-security-ux`
Timestamp: 2026-07-16 13:15 CDT

## Scope

Drafted current-folder search, safe MIME/HTML rendering foundation, remote-image blocking, CSP string, safe URL handling, attachment filename/size safety, and basic mobile/keyboard-safe non-SPA model through server-side data shapes.

## Verification

- `go test ./internal/webmail` covers current-folder search, HTML script/event stripping, javascript URL blocking, remote-image blocking, attachment filename traversal sanitization, size fallback, and CSP baseline.
- `go test ./...` passed before admission.
- `git diff --check -- .` passed before admission.

## Coverage gaps

Owner-directed admission accepted the current protocol-seam draft with known gaps recorded below.

## Known admitted gaps

- Full production IMAP client implementation remains future work.
- Full production SMTP submission integration remains future work.
- OpenPGP/MIME cryptographic signing integration, canonicalization, and verification remain future work beyond the structural seam checks.
- Hostile HTML/MIME rendering requires a real parser/sanitizer integration before production exposure.
- Full mobile/basic browser UI remains future work.
