# v4 raw MIME parser and text-only rendering evidence

Status: raw MIME hostile fixture coverage added; v4 rendering policy is explicitly conservative text-only for hostile HTML.

## Scope

Close the fake MIME/security gap that treated simple bodies as enough. This does not implement rich HTML rendering. It makes the product decision explicit: until a real parser-backed allowlist renderer and browser proof exist, HTML email is handled as hostile data and rendered as escaped text after removing high-risk active constructs.

## Implementation

- Added `webmail.ParseRawMessage`.
  - Parses raw RFC 5322 messages via `net/mail`.
  - Walks multipart MIME with bounded nesting and part counts.
  - Decodes common `Content-Transfer-Encoding` values: base64 and quoted-printable.
  - Extracts `text/plain`, `text/html`, and attachments.
  - Sanitizes attachment filenames/content-type through the existing `SafeAttachment` boundary.
  - Fails closed on invalid multipart boundaries, excessive nesting, excessive parts, and oversized content.
- Wired `NetIMAPClient.fetchMessage` through `ParseRawMessage` instead of dumping raw fetched MIME into `BodyText`.
- Added hostile corpus fixtures:
  - `test/fixtures/webmail/hostile-multipart.eml`
  - `test/fixtures/webmail/mime-part-flood.eml`

## Verification

- `go test -count=1 ./internal/webmail` passed.
- Hostile multipart fixture proves:
  - quoted-printable text body decode
  - hostile HTML remains data at parse time
  - text-only render boundary strips/escapes script/javascript/event/remote-image content
  - traversal-prone attachment filename is sanitized
  - base64 attachment payload is decoded
- Part-flood fixture proves excessive MIME part count fails closed.
- Invalid multipart boundary regression proves malformed multipart input fails closed.

## Remaining blockers

- Real OpenPGP/MIME signing/verification with exact-sender key-state matrix.
- Custom webmail UI/container reachability.
