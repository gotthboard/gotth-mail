# Implementation Spec — v4 Custom Webmail

Source PRD: [PRD-v4-webmail.md](../prd/PRD-v4-webmail.md)
Source architecture: [architecture/v4-webmail.md](../architecture/v4-webmail.md)

## Goal

If the v4 cutline is explicitly accepted, implement a custom GOTTH Mail webmail provider. Until then, supported external webmail remains required.

Custom webmail must remain separate from the control-plane product and must not replace Dovecot, SMTP submission, or core policy.

## Deployment

Custom webmail runs in the containerized GOTTH Mail API service and exposes the
interactive GOTTH Mail-owned `/webmail` client. Roundcube remains the external
provider reference, not the custom UI. The custom client may use a plugin seam
for provider registration/status, but it receives no authority over core
policy.

Control-plane mutations initiated from webmail must call core service/auth/audit paths.

## IMAP client

Required capabilities:

- folder list
- message list
- message read
- pagination/windowing
- quota display
- safe MIME parsing foundation

IMAP connection configuration is derived from a bounded protected runtime
registry. The production registry selects one exact mailbox entry and reloads
its owner-only password file for each connection. It delegates to
`webmail.NetIMAPClient`, which talks TCP IMAP to Dovecot for
folder/list/search/read/quota and message-action operations. Message IDs are
stable IMAP UIDs. Read/unread and flagged state use bounded `UID STORE`; move
uses `UID MOVE`; delete marks the exact UID deleted and uses `UID EXPUNGE`, so
it does not expunge unrelated messages. Plaintext IMAP is accepted only on a
loopback/private address or a single-label private service name. The webmail
client does not read mailbox files directly and does not replace Dovecot.

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

Sending uses SMTP submission. The production transport adapter is
`webmail.NetSMTPSubmitter`, which submits already-built/already-signed MIME
bytes over certificate-verified STARTTLS SMTP; signing, sender identity
binding, and policy remain in `webmail.Sender`, not in the transport adapter.

State machine:

```text
draft -> queued_for_submission -> submitted -> sent
                         |-> failed
                         |-> delivery_uncertain
```

Features:

- compose
- save drafts
- attachments
- reply/forward
- send failure reporting
- honest app-password/session boundary

Configured SQL draft storage persists mailbox ownership, submit state, reply/forward linkage, and attachment metadata/content. Draft creation at the API boundary ignores caller-supplied draft IDs and binds ownership to the authenticated mailbox; SQL edits require the same mailbox and an editable `draft`/`failed` state. Submission and editing therefore cannot race to revive a claimed draft. Saved-draft lists return summary fields only; the authenticated detail route loads body and attachment bytes when a draft is opened. Submission claims a draft with one conditional SQL update, so concurrent requests cannot produce duplicate SMTP attempts. `submitted`, `sent`, and `delivery_uncertain` drafts are not automatically retryable. Transport loss at the SMTP acceptance boundary becomes `delivery_uncertain` instead of an ordinary failure because an automatic retry could duplicate accepted mail.

`GOTTH_MAIL_WEBMAIL_RUNTIME_FILE` enables production wiring. The owner-only JSON
registry contains private-service IMAP/SMTP addresses and, per mailbox, paths
to distinct owner-only IMAP password, SMTP password, and OpenPGP private-key
files plus the required fingerprint. Password and key files are reloaded on
use, making rotation visible without storing cleartext credentials in the
database. The runtime declares the SMTP authentication mechanism explicitly.
Production uses PLAIN only after certificate-verified STARTTLS through the
private mail-front submission listener; PLAIN without STARTTLS is rejected at
startup. CRAM-MD5 remains available for bounded private test transports that
advertise it. Both mechanisms authenticate with the exact mailbox address;
that same identity is rechecked by outbound policy at submission and final
transport. Raw Postfix listeners requiring a HAProxy PROXY preamble are not
valid application submission endpoints. Startup fails on partial, unsafe,
duplicate, or mismatched configuration.

An active OIDC session bound to exactly one mailbox authorizes browser
webmail reads. Browser mutations additionally require the separate same-origin
CSRF cookie/header proof. Mailbox-scoped API bearer tokens remain supported for
non-browser clients, and no credential is stored in browser local storage.
SMTP submission must use
the configured mailbox credential and must not pretend OIDC is an SMTP
protocol. The sender cryptographically verifies the generated OpenPGP/MIME
signature, outer From, signed binding assertion, and fingerprint before any
SMTP command is allowed.

## Search and UX

Minimum v4 search scope is current-folder IMAP SEARCH with pagination/windowing and documented result limits. Any broader mailbox-wide index/search requires an amended v4 cutline and storage/security review before implementation.

The `/webmail` document and same-origin CSS/JavaScript assets implement the
three-pane contract without a SPA framework. The browser reads only through
the authenticated webmail API and keeps only non-secret theme/pane preferences
in local storage. It provides folder navigation, dense locally sortable rows,
current-folder search, reader, safe attachment downloads, compose/save/send,
saved-draft list/reopen/edit, reply/reply-all/forward, read/unread with folder
counts, attachment state, flag/unflag, move/delete, quota, pane placement and
resizing, keyboard commands, a context-menu accelerator with visible command
parity, responsive folder/list/reader drill-down, and light/dark themes. List
views fetch bounded header/flag metadata rather than complete message bodies.
Rules
are visibly unavailable when no Sieve service is configured rather than being
represented as working.

The server-rendered shell ends with the canonical GOTTH footer:
`Powered by GOTTH Mail`, `Version: <build>`, `Page: <milliseconds>`, and
`Template: <milliseconds>`. The build value comes from the validated
`internal/version` identity and is HTML-escaped before rendering. Page timing
starts at entry to the `/webmail` handler; template timing covers assembly of
the document shell up to the footer. Both values are emitted as non-negative
whole milliseconds. The footer is repository-owned CSS, fixed-dark in both
themes, responsive at narrow widths, and contains no commit hash or host data.

The UI implements the
[GOTTH Mail classic interface language](../reference/classic-interface-language.md)
with Go-rendered semantic markup, project-owned CSS tokens, and bounded
progressive enhancement. Outlook Classic is a workflow reference, not an asset
or branding source.

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

At narrow widths, CSS and bounded browser navigation collapse the three-pane view
into accounts/folders, message list, then reader or composer. Back navigation
retains the previous folder and safe list window. No mobile workflow depends
on hover, a secondary mouse button, or a squeezed desktop table.

Message activation uses a same-origin authenticated HTMX fragment request. The
fragment swaps the reading-pane content, then the narrow-width state exposes
that pane in the same viewport position while retaining the message list in the
DOM for immediate Back navigation. The fragment route accepts only an exact
`HX-Request: true`, returns escaped conservative message text, remains subject
to the existing mailbox authorization, and cannot carry executable message
markup. HTMX is pinned and self-hosted; evaluation, script tags, history, and
injected indicator styles are disabled. A narrow Trusted Types default policy
admits only HTMX's inert internal template wrapper when it begins with the
server-owned message-fragment marker; every other HTML sink assignment fails.

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
- custom `/webmail` client and same-origin assets are reachable from the
  repo-owned Compose `test-runner`
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
- canonical-footer checks for product identity, escaped exact build version,
  millisecond page/template timing fields, shared styling, and narrow layout
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
