# GOTTH Mail PRD — v4 Custom Webmail

## Goal

If the v4 cutline is explicitly accepted, v4 builds a custom GOTTH Mail webmail client after the control plane, daemon contracts, identity, operations, and import workflows are solid. Until then, the product requires a supported external webmail provider.

Custom webmail must not block the control-plane product.

## Scope

### v4.1 Webmail provider evolution

- Custom GOTTH Mail webmail becomes a webmail provider implementation for the accepted v4 scope.
- It remains separate from core mail policy.
- It is deployed as a containerized service/plugin.
- It must use the same auth/audit/service boundaries where it mutates state.

### v4.2 IMAP client core

- Folder list.
- Message list.
- Message read.
- IMAP pagination/windowing.
- Quota display.
- Safe MIME parsing foundation.

### v4.3 Compose/send

- SMTP submission.
- Drafts.
- Attachments.
- Reply/forward.
- Send failure reporting.
- App-password/session boundary handled honestly.

### v4.4 Mail UX

- Search.
- Identities/signatures.
- Sieve/rules UI if supported.
- An Outlook Classic-inspired but distinctly GOTTH Mail visual language, as
  defined by the
  [classic interface contract](../reference/classic-interface-language.md).
- Desktop-first three-pane navigation, dense message list, and configurable
  reading pane with a traditional command bar.
- Resizable panes, sortable columns, keyboard navigation, and context menus
  with equivalent visible and keyboard-accessible commands.
- Responsive mobile drill-down from folders to message list to reader or
  composer rather than a squeezed desktop layout.
- Restrained blue/gray light and dark themes using original or appropriately
  licensed assets.
- The canonical GOTTH product footer showing product identity, release
  version, page-render time, and template-render time.
- A shared visual language with the administration GUI without merging
  webmail and control-plane authority.

### v4.5 Security hardening

- XSS-safe HTML email rendering.
- Attachment handling.
- Remote image policy.
- MIME edge-case testing.
- Content Security Policy.
- No unsafe HTML bypass.

## Non-goals

- No custom webmail before v4.
- No replacing IMAP/SMTP daemons.
- No client-side SPA pile.
- No pretending webmail is the control plane.

## Acceptance criteria

- External webmail remains usable until custom webmail is production-ready.
- Custom webmail can read folders/messages through IMAP safely.
- Custom webmail can compose, save drafts, and submit messages.
- Search works across the supported mailbox scope declared for v4.
- Identities/signatures work for compose/send flows.
- HTML email rendering is XSS-hardened with CSP and no unsafe HTML bypass.
- Remote image policy is enforced.
- Attachments are handled safely.
- At desktop widths the primary workflow presents folder navigation, a dense
  sortable message list, and a reading pane that can be right, below, or off.
- The command bar, pane resizing, keyboard navigation, and context-menu
  accelerators remain accessible and have non-context-menu equivalents.
- Narrow layouts collapse predictably into folder, list, and reader/composer
  views while preserving safe navigation state.
- Light and dark themes preserve contrast, focus, selection, unread, flag,
  attachment, and error meaning without relying on color alone.
- The interface uses GOTTH Mail branding and original or appropriately
  licensed assets; it does not copy Microsoft trademarks, copyrighted icons,
  product artwork, or exact branding.
- The canonical dark GOTTH footer remains visible in both themes and reports
  `Powered by GOTTH Mail`, the exact build version, page time, and template
  time without exposing source revisions or other internal build metadata.
- Webmail UI does not bypass core authorization/audit paths for control-plane actions.

## Mandatory OpenPGP signing

This requirement is traced to [Exact Sender Identity Binding for OpenPGP/MIME Signed Email](../reference/openpgp-exact-sender/draft-hunn-openpgp-exact-sender-signatures-01.md) and, for search/audit/history behavior, [Operational Identity History and Audit Indexing for Exact Sender Binding](../reference/openpgp-exact-sender/draft-hunn-exact-sender-operational-identity-history-00.md).

Compose/send flows must OpenPGP-sign every outbound email with the sending user's configured signing identity. The UI may expose identity/signature state, but it may not offer a bypass that sends unsigned mail.

Required behavior:

- missing, expired, revoked, disabled, or mismatched signing key blocks send;
- signing failures are visible to the user and recorded in audit/doctor state;
- signatures use OpenPGP/MIME for MIME messages rather than ad-hoc headers;
- canonicalization and signed header/body coverage are specified and tested;
- DKIM signing remains domain-level proof and does not replace exact-user OpenPGP signatures.


The signature requirement is not merely provenance for a domain or server. Verification must answer exactly which configured user identity signed the message. If the signer cannot be mapped to the asserted From/Sender identity and active user/key binding, the message is treated as unsigned/invalid.
