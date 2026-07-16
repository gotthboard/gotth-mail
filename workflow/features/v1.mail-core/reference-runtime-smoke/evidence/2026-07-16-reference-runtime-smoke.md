# v1 reference runtime smoke evidence

Date/time: 2026-07-16 02:11 CDT

Commit: 9f1aa30fb3920aa2ba4ccc30ed3cdf6088de3d5a

## Scope implemented

Implemented `v1.mail-core.reference-runtime-smoke` to close the root admission blocker identified in `workflow/features/v1.mail-core/review/2026-07-16-root-admission-review.md`.

Added real reference runtime services:

- Postfix container running `postfix start-fg`
- Dovecot container running `dovecot -F`
- Rspamd container running `rspamd -f` with generated DKIM key material
- Roundcube external webmail provider container wired to Dovecot IMAP and Postfix SMTP

Added daemon/config integration for the reference runtime:

- `GMF_REFERENCE_FIXTURE=1` starts GopherMailForge with explicit `example.test` daemon fixture data
- fixture includes `smoke@example.test`, `postmaster@example.test`, and `alias@example.test -> smoke@example.test`
- Postfix calls the GopherMailForge policy socket during SMTP recipient handling and rejects unknown recipients from daemon contract decisions
- Postfix virtual mailbox/alias maps are generated at container boot by querying GopherMailForge internal HTTP/JSON contracts, then deliver into the shared Maildir volume
- Dovecot generates its passwd-file auth/userdb material at container boot after querying GopherMailForge `passdb` and `userdb` contracts; no checked-in plaintext passwd fixture remains
- Rspamd queries GopherMailForge DKIM/signing-decision contracts before key generation, runs as a Postfix milter, and DKIM-signs the delivered message

Added `scripts/reference-runtime-smoke.sh`, which starts the reference Compose stack and proves:

- GopherMailForge daemon contract endpoints are reachable
- real Postfix rejects `nobody@example.test` through the GopherMailForge policy socket
- real Postfix accepts SMTP for `alias@example.test` through the same policy socket
- alias expansion delivers the message into `smoke@example.test` Maildir
- real Dovecot accepts IMAP login using generated GopherMailForge-derived auth/userdb material and returns the delivered message subject
- Roundcube login succeeds over HTTP using the smoke mailbox and its IMAP-backed mail view exposes the delivered message subject
- real Rspamd runs in the Postfix milter path, DKIM-signs the delivered message, has generated DKIM material, and passes `rspamadm configtest`

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
- real Postfix queried the GopherMailForge policy socket, rejected an unknown recipient, accepted SMTP, and delivered alias mail to Maildir
- real Dovecot used generated GopherMailForge-derived auth/userdb material and IMAP login/read succeeded
- Roundcube external webmail provider exposed the delivered message through its IMAP-backed mail view
- real Rspamd ran in the Postfix milter path, DKIM-signed the delivered message, and validated config
```

## Coverage

Covered behavior:

- reference Compose includes actual Postfix, Dovecot, Rspamd, and webmail services
- real SMTP recipient policy queries GopherMailForge and rejects unknown recipients
- real SMTP session queues a message through Postfix after policy acceptance
- receive path writes the message to Maildir
- alias delivery from `alias@example.test` to `smoke@example.test` works
- real IMAP login/read works through Dovecot using generated auth/userdb material
- DKIM runtime key material exists, Rspamd config validates, and the delivered message contains `DKIM-Signature`
- selected Roundcube webmail provider visibility sees the delivered message through its IMAP-backed mail view

No accepted gap remains for the original root blocker. The webmail proof is not a Maildir file-server check; it uses the selected Roundcube provider login and mail view backed by Dovecot IMAP.

## Remaining root action

Run a fresh cold v1 root admission review before opening a v1 PR. Do not treat this evidence file alone as root admission; admission requires the reviewer to inspect the full branch and verification.
