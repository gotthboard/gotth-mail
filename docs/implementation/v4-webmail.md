# Implementation Spec — v4 Custom Webmail

Source PRD: [PRD-v4-webmail.md](../prd/PRD-v4-webmail.md)
Source architecture: [architecture/v4-webmail.md](../architecture/v4-webmail.md)

## Goal

If the v4 cutline is explicitly accepted, implement a custom GopherMailForge webmail provider. Until then, supported external webmail remains required.

Custom webmail must remain separate from the control-plane product and must not replace Dovecot, SMTP submission, or core policy.

## Deployment

Custom webmail runs as a separate containerized webmail provider implementation. It may use a plugin seam for provider registration/status, but it must not receive authority over core policy.

Control-plane mutations initiated from webmail must call core service/auth/audit paths.

## IMAP client

Required capabilities:

- folder list
- message list
- message read
- pagination/windowing
- quota display
- safe MIME parsing foundation

IMAP connection configuration is derived from core state/config. The webmail client does not read mailbox files directly and does not replace Dovecot.

Message list response shape:

```json
{
  "folder": "INBOX",
  "cursor": "opaque",
  "messages": [
    {
      "id": "opaque-imap-id",
      "from": "safe display",
      "subject": "safe text",
      "date": "...",
      "flags": ["Seen"]
    }
  ],
  "next_cursor": "opaque-or-null"
}
```

## Compose/send

Sending uses SMTP submission.

State machine:

```text
draft -> queued_for_submission -> submitted -> sent
                         |-> failed
```

Features:

- compose
- save drafts
- attachments
- reply/forward
- send failure reporting
- honest app-password/session boundary

Web session identity may authorize webmail access, but SMTP submission must use the configured submission path and must not pretend OIDC is an SMTP protocol.

## Search and UX

Minimum v4 search scope is current-folder IMAP SEARCH with pagination/windowing and documented result limits. Any broader mailbox-wide index/search requires an amended v4 cutline and storage/security review before implementation.

Features:

- identities/signatures
- sieve/rules UI if supported by Dovecot/config
- mobile layout
- keyboard-safe basic workflows

## MIME and HTML security

HTML email is hostile input.

Renderer requirements:

- sanitize HTML before rendering
- no unsafe HTML bypass
- baseline CSP: `default-src 'none'; img-src 'self' data:; style-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'`
- remote image policy enforced by default; remote images require explicit user action or configured proxy policy
- attachment content type and disposition rules
- MIME edge-case tests
- no script execution from message content
- safe URL handling with an allowlist for `http`, `https`, and `mailto`

Attachment handling:

- filenames sanitized for display
- no path traversal
- size limits
- content type treated as advisory, not authority

## Control-plane boundary

If webmail exposes actions such as aliases, identities, forwarding, sieve/rules, password/app-password UI, or mailbox settings, those actions must route through core service/auth/audit paths. Webmail cannot write canonical state directly.

## Verification

Required tests:

- external webmail remains usable until custom webmail is production-ready
- folder/message reads through IMAP with pagination/windowing
- quota display uses Dovecot/core contract
- compose/draft/submit/reply/forward flows
- send failures reported clearly
- current-folder IMAP SEARCH works with pagination/windowing and documented result limits
- identities/signatures work in compose/send
- HTML rendering XSS tests with CSP and no unsafe bypass
- remote image policy tests
- MIME edge-case tests
- attachment safety tests
- mobile/basic workflow smoke tests
- webmail control-plane actions route through core service/auth/audit paths without bypass
- `git diff --check`
- `go test ./...`

## Mandatory OpenPGP signing

Compose/send flows must OpenPGP-sign every outbound email with the sending user's configured signing identity. The UI may expose identity/signature state, but it may not offer a bypass that sends unsigned mail.

Required behavior:

- missing, expired, revoked, disabled, or mismatched signing key blocks send;
- signing failures are visible to the user and recorded in audit/doctor state;
- signatures use OpenPGP/MIME for MIME messages rather than ad-hoc headers;
- canonicalization and signed header/body coverage are specified and tested;
- DKIM signing remains domain-level proof and does not replace exact-user OpenPGP signatures.


The signature requirement is not merely provenance for a domain or server. Verification must answer exactly which configured user identity signed the message. If the signer cannot be mapped to the asserted From/Sender identity and active user/key binding, the message is treated as unsigned/invalid.
