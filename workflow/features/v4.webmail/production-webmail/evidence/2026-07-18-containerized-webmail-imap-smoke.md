# v4 containerized webmail IMAP smoke evidence

Status: production IMAP transport slice implemented and container-smoked against the reference Dovecot stack.

## Scope

Replace fake-only IMAP read coverage with a small real network IMAP adapter and prove it from a containerized test runner against repo-owned reference Dovecot.

This does not claim the full custom webmail is production-complete. MIME hostile parsing, rich HTML browser proof/UI reachability, and OpenPGP/MIME exact-sender send remain separate blockers.

## Implementation

- Added `webmail.NetIMAPClient`.
  - Plain TCP IMAP transport with context-bounded dial/deadline.
  - Authenticates with configured mailbox credentials.
  - Implements folder listing, message listing, message reading, search, and quota placeholder.
  - Uses `net/mail` for message header/body extraction after fetching raw message bytes.
  - Treats IMAP `INBOX` as always present and filters Dovecot namespace delimiter noise (`.`) from folders.
- Added `internal/webmail/imap_test.go`.
  - Fake-server coverage for folder/list/search/read flow.
  - Parser coverage for quoted and atom mailbox names.
  - Env-gated live Compose Dovecot test using `GMF_LIVE_IMAP_ADDR`, `GMF_LIVE_IMAP_USER`, and `GMF_LIVE_IMAP_PASSWORD`.
- Added `scripts/containerized-webmail-imap-smoke.sh`.
  - Starts reference Compose `gophermailforge`, `postfix`, `dovecot`, and `rspamd` services.
  - Injects a marker message through the real webmail SMTP submitter path.
  - Runs live IMAP adapter tests inside the Compose `test-runner` container against `dovecot:143`.
- Hardened container smoke scripts to rebuild `test-runner` before running tests, so stale test-runner images cannot hide source changes.

## Verification

- `go test -count=1 ./internal/webmail ./test/contract` passed.
- `scripts/containerized-webmail-imap-smoke.sh` passed after fixing stale test-runner rebuild behavior and Dovecot LIST namespace parsing.
  - The Docker build stage ran `go test ./...` inside the container.
  - SMTP injection through Compose Postfix delivered the marker message.
  - The live IMAP adapter test reached `dovecot:143`, listed folders with `INBOX`, and read the delivered marker message.

## Remaining blockers

- Real OpenPGP/MIME signing/verification with exact-sender key-state matrix.
- Raw MIME parser and hostile fixture corpus.
- Parser-backed rich HTML sanitizer or explicit text-only product decision with browser proof.
- Attachment/reply/forward draft metadata durability beyond the current durable base fields.
- Custom webmail UI/container reachability.
