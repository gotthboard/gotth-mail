# Architecture — v4 Custom Webmail

Source PRD: [PRD-v4-webmail.md](../prd/PRD-v4-webmail.md)

## Goal

If the v4 cutline is explicitly accepted, v4 builds a custom GOTTH Mail webmail client. Until then, supported external webmail remains required.

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

Production webmail submits through the mail front's private submission
listener with STARTTLS and mailbox-bound PLAIN authentication. The TLS server
name is explicit and certificate-verified. Raw Postfix listeners that require
the HAProxy PROXY preamble are backend implementation details, not application
submission endpoints.

Features:

- compose
- save drafts
- submit message
- attachments
- reply/forward
- send failure reporting
- honest app-password/session boundary

## Mail UX architecture

The presentation follows the
[GOTTH Mail classic interface language](../reference/classic-interface-language.md).
It borrows the familiar workflow density of Outlook Classic without copying
Microsoft branding or assets.

The desktop composition has three regions: account/folder navigation, a dense
sortable message list, and a configurable reading pane. The reading pane can
be placed to the right, placed below, or hidden, and pane dimensions can be
resized within accessible minimums. A traditional command bar exposes primary
mail actions without hiding required operations behind a context menu.

Features and interaction requirements:

- search across supported mailbox scope
- identities/signatures
- sieve/rules UI if supported
- semantic keyboard navigation and documented shortcuts
- context menus with equivalent visible and keyboard-accessible commands
- light and dark GOTTH blue/gray themes with original or appropriately
  licensed icons
- deterministic mobile drill-down from folders to list to reader/composer

The administration GUI shares design tokens and applicable navigation,
command, and table patterns so the product feels coherent. It remains a
separate control surface, and presentation reuse grants webmail no additional
authority.

Go-rendered markup provides the authoritative page structure. Repository-owned
CSS variables and rules supply the visual tokens without a runtime or build
framework dependency. Bounded progressive enhancement updates panes and
commands; it is not a client-side SPA state authority.

The document shell ends with the shared GOTTH product footer. The server
renders the exact admitted build version and bounded millisecond page/template
timings into escaped markup. The footer exposes no commit hash, dirty-tree
state, hostname, or other operational metadata. It uses the same fixed dark
presentation in both application themes so the cross-product identity remains
consistent.

## Security architecture

Required hardening:

- XSS-safe HTML email rendering
- remote image policy
- MIME edge-case testing
- Content Security Policy
- no unsafe HTML bypass
- attachment handling rules
- keyboard focus, reflow, contrast, reduced-motion, and non-color state cues
- original GOTTH presentation with no copied Microsoft trademarks, logos,
  copyrighted icons, product artwork, or exact branding

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
- three-pane desktop layout, command bar, reading-pane placement, resizing,
  sorting, keyboard, and context-menu behavior pass interaction tests
- mobile drill-down, focus preservation, zoom/reflow, and light/dark contrast
  pass accessibility-oriented browser checks
- every context-menu action has an equivalent visible and keyboard-accessible
  path
- only original or appropriately licensed presentation assets ship
- the canonical footer renders product, build version, page time, and template
  time in desktop and narrow layouts without exposing internal build metadata
- webmail control-plane actions route through core service/auth/audit paths without bypass

## Mandatory OpenPGP signing

Architecture must conform to [Exact Sender Identity Binding for OpenPGP/MIME Signed Email](../reference/openpgp-exact-sender/draft-hunn-openpgp-exact-sender-signatures-01.md). Any identity history, search, audit indexing, downgrade detection, key rotation continuity, or forensic export behavior must conform to [Operational Identity History and Audit Indexing for Exact Sender Binding](../reference/openpgp-exact-sender/draft-hunn-exact-sender-operational-identity-history-00.md).

Compose/send flows must OpenPGP-sign every outbound email with the sending user's configured signing identity. The UI may expose identity/signature state, but it may not offer a bypass that sends unsigned mail.

Required behavior:

- missing, expired, revoked, disabled, or mismatched signing key blocks send;
- signing failures are visible to the user and recorded in audit/doctor state;
- signatures use OpenPGP/MIME for MIME messages rather than ad-hoc headers;
- canonicalization and signed header/body coverage are specified and tested;
- DKIM signing remains domain-level proof and does not replace exact-user OpenPGP signatures.


The signature requirement is not merely provenance for a domain or server. Verification must answer exactly which configured user identity signed the message. If the signer cannot be mapped to the asserted From/Sender identity and active user/key binding, the message is treated as unsigned/invalid.
