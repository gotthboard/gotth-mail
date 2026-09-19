# Production webmail runtime wiring

Date: 2026-09-19 12:52 CDT

State: production transport/signing runtime checkpoint complete; feature
remains in progress pending the interactive custom UI and final admission.

## Closed gaps

- `cmd/gotth-mail` now installs `WebmailClient` and `WebmailSender` when the
  explicit protected runtime registry is configured; it no longer leaves the
  production API at an unwired 503 seam.
- The registry binds each authenticated mailbox to separate owner-only IMAP
  and SMTP password files, one exact signing fingerprint, and one owner-only
  private-key file. It rejects duplicate mailboxes, unsafe public plaintext
  endpoints, unknown/trailing JSON, loose file permissions, ambiguous keys,
  identity drift, revoked/expired/locked keys, and unsupported signing hashes.
- IMAP quota is mailbox-scoped and parsed from `GETQUOTAROOT`; the API exposes
  exact used/limit byte counts at `/api/v1/webmail/quota`.
- Webmail now cryptographically verifies its generated OpenPGP/MIME exact
  sender proof before SMTP instead of checking parser shape alone.
- SQL submission uses one conditional claim. A submitted, sent, or uncertain
  draft cannot be claimed again. SMTP acceptance uncertainty is durably stored
  as `delivery_uncertain` by migration `0012` and is never blindly retried.
- Invalid recipients move an already-claimed draft to `failed` instead of
  stranding it in `queued_for_submission`.

## Verification

- Focused store, webmail, API, and command tests passed on the development
  host, including migration parity, secret/key permission drift, exact-sender
  verification-before-SMTP, quota parsing, runtime wiring, one-time SQL claim,
  and ambiguous-delivery duplicate suppression.
- The rebuilt reference stack started the real `gotth-mail` binary with the
  protected runtime registry. A fresh GnuPG RSA signing identity was generated
  only in a disposable directory, mounted read-only, loaded by the production
  registry, and removed by the cleanup trap.
- `TestRuntimeRegistryLiveComposeFlow` built MIME, resolved the exact mailbox
  identity, signed and cryptographically verified it, authenticated to real
  Postfix as that mailbox, passed outbound policy/final transport, delivered to
  Dovecot, found the message through real IMAP search, and read the configured
  Dovecot quota through `GETQUOTAROOT`.
- The Compose project and volumes were removed after the smoke.

## Boundaries

- No production credential, mailbox, queue, deployment, DNS record, tag,
  release, or external service changed.
- The static reachability shell is not represented as a finished interactive
  webmail client. That remaining UI work stays explicit.
