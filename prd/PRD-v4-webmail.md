# GopherMailForge PRD — v4 Custom Webmail

## Goal

If the v4 cutline is explicitly accepted, v4 builds a custom GopherMailForge webmail client after the control plane, daemon contracts, identity, operations, and import workflows are solid. Until then, the product requires a supported external webmail provider.

Custom webmail must not block the control-plane product.

## Scope

### v4.1 Webmail provider evolution

- Custom GopherMailForge webmail becomes a webmail provider implementation for the accepted v4 scope.
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
- Mobile layout.
- Keyboard-safe basic workflows.

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
- Mobile/basic workflows are usable.
- Webmail UI does not bypass core authorization/audit paths for control-plane actions.
