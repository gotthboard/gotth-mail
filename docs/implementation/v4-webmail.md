# Implementation Spec — v4 Custom Webmail

Source PRD: [PRD-v4-webmail.md](../prd/PRD-v4-webmail.md)
Source architecture: [architecture/v4-webmail.md](../architecture/v4-webmail.md)

## Goal

If the v4 cutline is explicitly accepted, implement a custom GOTTH Mail webmail provider. Until then, supported external webmail remains required.

Custom webmail must remain separate from the control-plane product and must not replace Dovecot, SMTP submission, or core policy.

## Deployment

Custom webmail runs as a containerized webmail provider implementation and now exposes a minimal GOTTH Mail-owned `/webmail` shell from the API container for reachability proof. Roundcube remains the external provider reference, not the custom UI. The custom shell may use a plugin seam for provider registration/status, but it must not receive authority over core policy.

Control-plane mutations initiated from webmail must call core service/auth/audit paths.

## IMAP client

Required capabilities:

- folder list
- message list
- message read
- pagination/windowing
- quota display
- safe MIME parsing foundation

IMAP connection configuration is derived from core state/config. The production transport adapter is `webmail.NetIMAPClient`, which talks TCP IMAP to Dovecot for folder/list/search/read operations. The webmail client does not read mailbox files directly and does not replace Dovecot.

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

Sending uses SMTP submission. The production transport adapter is `webmail.NetSMTPSubmitter`, which submits already-built/already-signed MIME bytes over TCP SMTP; signing, sender identity binding, and policy remain in `webmail.Sender`, not in the transport adapter.

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

Configured SQL draft storage persists mailbox ownership, submit state, reply/forward linkage, and attachment metadata/content. Draft creation at the API boundary ignores caller-supplied draft IDs and binds ownership to the authenticated mailbox; SQL updates refuse cross-mailbox overwrites.

Web session identity may authorize webmail access, but SMTP submission must use the configured submission path and must not pretend OIDC is an SMTP protocol.

## Search and UX

Minimum v4 search scope is current-folder IMAP SEARCH with pagination/windowing and documented result limits. Any broader mailbox-wide index/search requires an amended v4 cutline and storage/security review before implementation.

The UI implements the
[GOTTH Mail classic interface language](../reference/classic-interface-language.md)
with server-rendered Go templates, project-owned Tailwind tokens, and HTMX or
bounded progressive enhancement. Outlook Classic is a workflow reference, not
an asset or branding source.

Desktop layout contract:

- left navigation pane: accounts, favorites, folders, and unread counts
- center pane: compact sortable message rows with sender, subject preview,
  received time, flags, and attachment state
- reading pane: right, below, or hidden, with dimensions resizable within
  accessible minimums
- traditional command bar: new, reply, reply all, forward, delete, move,
  mark, rules, and search as applicable to current state

Interaction contract:

- identities/signatures
- sieve/rules UI if supported by Dovecot/config
- semantic list/table and command markup with visible focus
- arrow-key navigation, selection, activation, and documented shortcuts
- context menus only as accelerators; every action also has a visible and
  keyboard-accessible path
- sort state announced semantically and never conveyed by color/icon alone
- light and dark restrained blue/gray themes with equivalent contrast and
  state meaning
- original GOTTH or appropriately licensed icons with accessible names

At narrow widths, CSS and server/HTMX navigation collapse the three-pane view
into accounts/folders, message list, then reader or composer. Back navigation
retains the previous folder and safe list window. No mobile workflow depends
on hover, a secondary mouse button, or a squeezed desktop table.

The admin GUI reuses applicable tokens, navigation, table, command, focus, and
status patterns. Administrative actions remain visually explicit and continue
through core service/auth/audit paths. Shared CSS or templates must not combine
the webmail session model with control-plane authority.

Do not include Microsoft trademarks, logos, copyrighted icons, product
artwork, proprietary strings, or exact branding. Similarity is limited to the
general three-pane workflow and information density.

## MIME and HTML security

HTML email is hostile input.

Renderer requirements:

- v4 rendering decision: HTML email is rendered as conservative escaped text, not rich HTML, until a real parser-backed allowlist renderer and browser proof are admitted
- no unsafe HTML bypass
- baseline CSP: `default-src 'none'; img-src 'self' data:; style-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'`
- remote image policy enforced by default; remote URLs are removed/blocked by the text-only render boundary
- attachment content type and disposition rules
- MIME edge-case tests using hostile raw message fixtures
- no script execution from message content
- safe URL handling must be reviewed again before any future rich-HTML renderer is admitted

Raw MIME parsing is handled by `webmail.ParseRawMessage`, which bounds message size, multipart nesting, part count, and per-part content size; decodes base64 and quoted-printable parts; extracts plain text, HTML-as-data, and attachments; and fails closed on malformed multipart boundaries.

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
- custom `/webmail` shell is reachable from the repo-owned Compose `test-runner`
- folder/message reads through IMAP with pagination/windowing
- quota display uses Dovecot/core contract
- compose/draft/submit/reply/forward flows
- send failures reported clearly
- current-folder IMAP SEARCH works with pagination/windowing and documented result limits
- identities/signatures work in compose/send, including exact sender identity binding and fail-closed mismatches
- HTML rendering XSS tests with CSP and no unsafe bypass
- remote image policy tests
- MIME edge-case tests
- attachment safety tests
- desktop browser checks for three panes, dense rows, command availability,
  sortable columns, reading-pane right/below/off placement, and bounded pane
  resizing
- keyboard checks for focus order, navigation, selection, activation,
  shortcuts, command parity, and context-menu alternatives
- responsive browser checks for folder -> list -> reader/composer drill-down,
  back-state preservation, touch target size, zoom, and text reflow
- light/dark theme checks for contrast and non-color focus, selection, unread,
  flag, attachment, success, warning, and error cues
- asset provenance check proving shipped icons and artwork are original or
  appropriately licensed and contain no Microsoft branding
- webmail control-plane actions route through core service/auth/audit paths without bypass
- `git diff --check`
- `go test ./...`

## Mandatory OpenPGP signing

Implementation must conform to [Exact Sender Identity Binding for OpenPGP/MIME Signed Email](../reference/openpgp-exact-sender/draft-hunn-openpgp-exact-sender-signatures-01.md). Search/audit behavior related to exact sender identity must conform to [Operational Identity History and Audit Indexing for Exact Sender Binding](../reference/openpgp-exact-sender/draft-hunn-exact-sender-operational-identity-history-00.md).

Compose/send flows must OpenPGP-sign every outbound email with the sending user's configured signing identity. The implemented `OpenPGPMIMESigner` emits `multipart/signed` with `protocol="application/pgp-signature"` and `micalg=pgp-sha256` using the maintained ProtonMail OpenPGP fork. The implemented verifier checks the detached signature, visible outer From, signed sender-binding assertion, and expected fingerprint before accepting exact sender proof. The UI may expose identity/signature state, but it may not offer a bypass that sends unsigned mail.

Required behavior:

- missing, expired, revoked, disabled, or mismatched signing key blocks send;
- signing failures are visible to the user and recorded in audit/doctor state;
- signatures use OpenPGP/MIME for MIME messages rather than ad-hoc headers;
- canonicalization and signed header/body coverage are specified and tested;
- DKIM signing remains domain-level proof and does not replace exact-user OpenPGP signatures.
- production key storage/unlock lifecycle is deployment-specific, but the core sender path fails closed when signing or exact-sender validation cannot complete.


The signature requirement is not merely provenance for a domain or server. Verification must answer exactly which configured user identity signed the message. If the signer cannot be mapped to the asserted From/Sender identity and active user/key binding, the message is treated as unsigned/invalid.
