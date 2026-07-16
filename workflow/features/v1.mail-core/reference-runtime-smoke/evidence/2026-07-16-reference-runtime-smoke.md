# v1 reference runtime smoke evidence

Date/time: 2026-07-16 02:11 CDT

Commit: current commit; hash assigned by Git after commit

## Scope implemented

Implemented `v1.mail-core.reference-runtime-smoke` to close the root admission blocker identified in `workflow/features/v1.mail-core/review/2026-07-16-root-admission-review.md`.

Added real reference runtime services:

- Postfix container running `postfix start-fg`
- Dovecot container running `dovecot -F`
- Rspamd container running `rspamd -f` with generated DKIM key material
- webmail visibility container exposing the Maildir over HTTP for smoke proof

Added daemon/config integration for the reference runtime:

- `GMF_REFERENCE_FIXTURE=1` starts GopherMailForge with explicit `example.test` daemon fixture data
- fixture includes `smoke@example.test`, `postmaster@example.test`, and `alias@example.test -> smoke@example.test`
- Postfix virtual mailbox/alias maps are generated from reference config and deliver into the shared Maildir volume
- Dovecot authenticates `smoke@example.test` with the same Django PBKDF2-SHA256 verifier shape used by the daemon contract tests
- Rspamd generates DKIM material for `example.test` selector `mail` and validates its runtime config

Added `scripts/reference-runtime-smoke.sh`, which starts the reference Compose stack and proves:

- GopherMailForge daemon contract endpoints are reachable
- real Postfix accepts SMTP for `alias@example.test`
- alias expansion delivers the message into `smoke@example.test` Maildir
- real Dovecot accepts IMAP login and returns the delivered message subject
- webmail visibility can fetch the delivered Maildir message body over HTTP
- real Rspamd has generated DKIM material and passes `rspamadm configtest`

## Verification performed

Passed:

```text
go test ./...
git diff --check -- .
scripts/reference-runtime-smoke.sh
```

Observed smoke result:

```text
reference runtime smoke passed:
- GopherMailForge daemon contracts reachable
- real Postfix accepted SMTP and delivered alias mail to Maildir
- real Dovecot IMAP login/read succeeded
- webmail provider exposed delivered Maildir message
- real Rspamd started with generated DKIM key material and valid config
```

## Coverage

Covered behavior:

- reference Compose includes actual Postfix, Dovecot, Rspamd, and webmail services
- real SMTP session queues a message through Postfix
- receive path writes the message to Maildir
- alias delivery from `alias@example.test` to `smoke@example.test` works
- real IMAP login/read works through Dovecot
- DKIM runtime key material exists and Rspamd config validates
- selected webmail visibility sees the delivered message body

No accepted gap remains for the original root blocker.

## Remaining root action

Run a fresh cold v1 root admission review before opening a v1 PR. Do not treat this evidence file alone as root admission; admission requires the reviewer to inspect the full branch and verification.
