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

Admission pending; no accepted coverage gap shall be recorded until cold review passes.
