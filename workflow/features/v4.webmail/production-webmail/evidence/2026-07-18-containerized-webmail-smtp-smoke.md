# v4 containerized webmail SMTP smoke evidence

Status: production SMTP transport slice implemented and container-smoked against the reference Postfix/Dovecot/Rspamd stack.

## Scope

Replace the fake-only webmail SMTP transport seam with a real network SMTP submitter and prove it from a containerized test runner against the repo-owned reference Compose mail stack.

This does not claim the full webmail send path is production-complete because mandatory OpenPGP/MIME signing and exact-sender key-state verification remain incomplete.

## Implementation

- Added `webmail.NetSMTPSubmitter`.
  - Validates envelope sender and recipients using `net/mail` before transport.
  - Refuses empty recipient lists and empty message bodies.
  - Uses `net.Dialer.DialContext` and SMTP client exchange over TCP.
  - Keeps policy, OpenPGP signing, and exact sender identity binding in `webmail.Sender`; the adapter only transports already-built/signed MIME bytes.
- Added `internal/webmail/smtp_test.go`.
  - Unit-smokes SMTP command flow against an in-test SMTP server.
  - Adds env-gated live Compose Postfix test using `GMF_LIVE_SMTP_ADDR`.
- Added `scripts/containerized-webmail-smtp-smoke.sh`.
  - Starts the reference Compose `gophermailforge`, `postfix`, `dovecot`, and `rspamd` services.
  - Runs the live SMTP submitter test inside the Compose `test-runner` container with `GMF_LIVE_SMTP_ADDR=postfix:25`.
  - Verifies Postfix delivers the submitted message into the smoke mailbox Maildir.
- Added contract coverage so the containerized SMTP smoke cannot silently disappear.

## Verification

- `go test -count=1 ./internal/webmail ./test/contract` passed.
- `git diff --check -- .` passed.
- `scripts/containerized-webmail-smtp-smoke.sh` passed.
  - The Docker build stage ran `go test ./...` inside the container.
  - The env-gated live SMTP submitter test passed against `postfix:25`.
  - The script verified delivery into `/mail/example.test/smoke/new`.

## Remaining blockers

- Production IMAP adapter and live Dovecot smoke.
- Real OpenPGP/MIME signing/verification with exact-sender key-state matrix.
- Raw MIME parser and hostile fixture corpus.
- Parser-backed rich HTML sanitizer or explicit text-only product decision with browser proof.
- Attachment/reply/forward draft metadata durability beyond the current durable base fields.
- Custom webmail UI/container reachability.
