# Architecture — v4 Custom Webmail

Source PRD: [PRD-v4-webmail.md](../prd/PRD-v4-webmail.md)

## Goal

If the v4 cutline is explicitly accepted, v4 builds a custom GopherMailForge webmail client. Until then, supported external webmail remains required.

Custom webmail must not block or contaminate the control-plane product.

## Deployment architecture

Custom webmail becomes a webmail provider implementation for the accepted v4 scope.

It is deployed as a containerized service/plugin and remains separate from core mail policy.

Control-plane mutations from webmail use the same service/auth/audit boundaries as other UI/API paths.

## IMAP client architecture

Core features:

- folder list
- message list
- message read
- IMAP pagination/windowing
- quota display
- safe MIME parsing foundation

The webmail client does not replace Dovecot.

## Compose/send architecture

Sending uses SMTP submission.

Features:

- compose
- save drafts
- submit message
- attachments
- reply/forward
- send failure reporting
- honest app-password/session boundary

## Mail UX architecture

Features:

- search across supported mailbox scope
- identities/signatures
- sieve/rules UI if supported
- mobile layout
- keyboard-safe basic workflows

## Security architecture

Required hardening:

- XSS-safe HTML email rendering
- remote image policy
- MIME edge-case testing
- Content Security Policy
- no unsafe HTML bypass
- attachment handling rules

HTML email is hostile input. Treat it as data, not UI code.

## Non-goals

- no custom webmail before v4
- no replacing IMAP/SMTP daemons
- no client-side SPA pile
- no pretending webmail is the control plane

## Verification gates

- external webmail remains usable until custom webmail is production-ready
- custom webmail reads folders/messages through IMAP safely
- compose/drafts/submit work
- search works across declared supported scope
- identities/signatures work in compose/send
- HTML rendering is XSS-hardened with CSP and no unsafe bypass
- remote image policy enforced
- attachments handled safely
- mobile/basic workflows usable
- webmail control-plane actions route through core service/auth/audit paths without bypass
