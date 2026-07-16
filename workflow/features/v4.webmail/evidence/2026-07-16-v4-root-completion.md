# v4 webmail root completion evidence

Root feature: `v4.webmail`
Timestamp: 2026-07-16 13:15 CDT

## Completed children

- `v4.webmail.provider-imap-compose`
- `v4.webmail.search-security-ux`

## Root admitted seam/model coverage

- External webmail continuity remains represented and required until custom provider is production-ready.
- Custom webmail reads folders/messages through IMAP-modeled interfaces with pagination/windowing.
- Quota display uses mailbox contract data.
- Compose/draft/submit behavior requires exact active OpenPGP/MIME signing structure validation identity; unsigned send fails.
- Current-folder search works with pagination/windowing.
- HTML rendering strips scripts/events, blocks javascript URLs, blocks remote images, and provides CSP baseline.
- Attachments sanitize traversal-prone filenames and enforce safety fallback for oversized content.
- Webmail remains separate from control-plane policy; control-plane mutation bypass is not introduced.

## Verification

- `git diff --check -- .` passed.
- `go test ./...` passed.

## Coverage gaps

Owner-directed admission accepted v4 as the current protocol-seam cut with known gaps recorded below.

## Known admitted gaps

- Full production IMAP client implementation remains future work.
- Full production SMTP submission integration remains future work.
- OpenPGP/MIME cryptographic signing integration, canonicalization, and verification remain future work beyond the structural seam checks.
- Hostile HTML/MIME rendering requires a real parser/sanitizer integration before production exposure.
- Full mobile/basic browser UI remains future work.
