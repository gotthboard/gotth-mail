# v4 admission repair evidence

Root feature: `v4.webmail`
Timestamp: 2026-07-18 CDT

## Repair slice

Layered vertical slice: webmail API reachability, exact-sender binding seam, safe MIME construction, bounded search, draft identity, and hostile-content rendering boundary.

## What changed

- Wired `internal/webmail` into authenticated `/api/v1/webmail/*` routes for folders, list/search/read, draft save, and draft submit.
- Webmail API routes require bearer-token authentication with an explicit `mailbox:<address>:webmail:use` scope; folders, list/search/read, and draft sender binding all use that scoped mailbox instead of trusting a token ID or request body.
- Added an exact-sender resolver seam before signing; signer self-report alone is no longer accepted as sender authority.
- MIME construction now rejects CRLF subject injection, parses From/To addresses, emits RFC 5322 From/To/Date/Subject/MIME-Version headers, quotes multipart boundaries, and uses MIME header formatting for attachment filenames.
- Search now sends cursor and bounded `limit+1` request parameters to the IMAP boundary instead of pulling all results into memory and paginating locally.
- Draft IDs are generated with random tokens instead of recipient-derived IDs that collide and overwrite.
- HTML rendering no longer pretends regex sanitization is a security boundary; hostile HTML is treated as escaped text with dangerous controls and high-risk active constructs stripped before escaping.
- API tests prove webmail routes are reachable through the API layer, reject anonymous access, and bind draft `From`/IMAP read operations to the authenticated mailbox scope.

## Verification

- `go test ./internal/webmail` passed.
- `go test ./internal/api` passed.
- `git diff --check -- .` passed.
- `go test ./...` passed.

## Remaining gaps

- Production IMAP and SMTP adapters are still seams, not live network integrations.
- OpenPGP cryptographic signing/canonicalization remains a signer integration seam; this repair enforces resolver-before-signer identity binding at the webmail sender boundary.
- A real HTML parser/allowlist sanitizer is still required before rich HTML rendering is exposed; current behavior is deliberately conservative text rendering.
