# Webmail SMTP STARTTLS repair

Date: 2026-09-26 CDT

## Failure

Reply/send returned `SMTP submission failed before acceptance`. The live
Postfix trace showed the control-plane container connecting directly to the
backend listener, followed by `haproxy read: timeout error` and
`commands=0/0`. That listener requires a HAProxy PROXY preamble. The webmail
client waited for an SMTP greeting while Postfix waited for the preamble.

The next boundary was also incompatible: the runtime required CRAM-MD5 while
the production mail front advertises PLAIN and LOGIN only after STARTTLS.

## Repair

- Implementation commit:
  `259134a1eb0e89b2a813377860a94183c55ddef1`.
- Runtime configuration declares `smtp_auth_mechanism` explicitly.
- Production submission targets `front:1587`, requires STARTTLS, verifies the
  certificate for `mail.alhstudios.com`, and authenticates as the exact
  mailbox address with the protected SMTP password.
- PLAIN authentication without STARTTLS is rejected during startup.
- Missing STARTTLS is rejected before any AUTH command.
- Raw Postfix remains behind the existing front and policy boundaries; no
  direct queue injection or Postfix bypass was added.

## Verification

- Agent-host focused `./internal/webmail` tests: PASS.
- Development-host all-package compile (`go test -run '^$' ./...`): PASS.
- Development-host focused runtime/SMTP tests: PASS.
- The same focused tests under the race detector: PASS.
- `git diff --check`: PASS.
- The mail-front certificate chain for `mail.alhstudios.com`: verified with
  return code 0.
- A test binary built from the exact implementation commit ran against the
  live private network and protected runtime material. It negotiated
  STARTTLS, authenticated with PLAIN, submitted one signed local verification
  message, and found the message over IMAP. Postfix recorded one authenticated
  transaction with `ehlo=1 auth=1 mail=1 rcpt=1 data=1 quit=1 commands=6`, and
  LMTP returned `dsn=2.0.0 status=sent`.
- That broad live runtime test then failed only because its fixture expects at
  least two folders while this mailbox has only INBOX. The folder tree was not
  mutated merely to make the test green.

## Broad-suite coverage gap

The normal broad package run reached unrelated SQL tests but their temporary
PostgreSQL servers never became reachable. Webmail draft-store, notification,
SCIM, database, and Postfix-policy fixtures all reported connection refused on
different ephemeral ports. This is the existing PostgreSQL test-helper
startup/socket defect, not a transport assertion failure. Compilation of all
packages and all changed transport/runtime tests, including race coverage,
passed.

## Live candidate

- Release path:
  `/opt/gotth-mail-test/releases/dev-smtp-starttls-259134a-20260926T165738Z`.
- Runtime version: `dev`.
- Control-plane image:
  `sha256:a66ac1e66464b9051329562cf01192a0e685bacb81000b406ae8ad8f2563346c`.
- Source-state digest:
  `a7dd2ce19730ebd017c9fbc2105ed9be5083e2a203e804b10a4300d815dd7a3d`.
- Retained image archive SHA-256:
  `2a93e0ee12241a0cac6278ccf063b972d7f100c63b3c0542e14c98dd3c9e1e32`.
- The release-specific runtime directory is mode `0700`; its JSON file is mode
  `0600`, owned by runtime UID/GID `1000:1000`, and mounted read-only.
- All six containers are healthy. The GOTTH Mail deployment unit and Caddy are
  active. Ports 25, 143, 465, 587, and 993 are reachable. The Postfix queue is
  empty. The public footer reports `Version: dev`.

## Rollback and remaining boundary

Immediate rollback is the prior accepted candidate at
`/opt/gotth-mail-test/releases/dev-signed-out-shell-ca14f01-20260926T150503Z`.
Its compose file still mounts the original legacy runtime JSON, so rollback
does not inherit fields the older binary cannot parse. Immutable
`v1.0.0-alpha.2` remains retained behind that candidate.

This repair closes SMTP acceptance and local delivery. External delivery is
still deliberately incomplete until either a managed authenticated relay is
configured or direct delivery is admitted with PTR and DKIM. No fake success
claim is made for that separate transport boundary.
