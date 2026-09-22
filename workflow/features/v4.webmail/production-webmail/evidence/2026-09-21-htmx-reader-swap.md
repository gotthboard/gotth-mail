# HTMX responsive message-reader swap

Date: 2026-09-21 CDT

## Scope

Danny rejected the narrow-screen behavior where the reading pane could remain
below the list and require scrolling. Message activation must replace the
visible list stage with the reader, using HTMX, while Back restores the retained
list and selection.

This repair is limited to Web Mail navigation and reader sizing. It does not
change authentication, mailbox authorization, CSRF enforcement, IMAP mutation,
SMTP submission, DNS administration, or release identity.

## Mechanism

- Dynamic message rows issue an authenticated same-origin HTMX GET to
  `/webmail/fragments/message` and target the existing reading pane.
- The handler requires exact `HX-Request: true`, reuses the bound mailbox
  authorization path, performs one bounded message read, and server-renders
  escaped conservative text plus safe attachment links.
- At widths through 1024 CSS pixels, the existing deterministic state hides the
  retained list and exposes the swapped reader at the same viewport position.
  Back restores the list without refetching or losing its current window.
- The fragment retains the reader's empty-state nodes so delete and move keep
  their prior desktop behavior after a swap. HTMX authorization failures carry
  their HTTP status into the existing sign-in/error handling path.
- HTMX 2.0.10 is self-hosted at SHA-256
  `71ea67185bfa8c98c39d31717c6fce5d852370fcdfd129db4543774d3145c0de`;
  its 0BSD license is retained beside the asset.
- HTMX evaluation, response scripts, history, and injected indicator styles are
  disabled. Trusted Types remains required. The only admitted default policy
  accepts HTMX's inert internal template wrapper only when it begins with the
  server-owned message-fragment marker; every other HTML sink assignment fails.

## Verification

- Expected-red: `scripts/webmail-browser-smoke.mjs` failed with
  `pinned HTMX runtime missing` before production code changed.
- Focused API tests prove exact HTMX request admission, bound authorization,
  escaped hostile message HTML, no-store/Vary headers, asset identity, and CSP.
- The complete Go suite, focused API race tests, and `go vet` passed on the
  development host. The test environment uses the short `/t` temporary path;
  longer task-specific paths exceed PostgreSQL's Unix-socket path limit.
- Real Chromium proves the HTMX fragment request, desktop reader operation,
  980-pixel drill-down, a 390-pixel reader wholly inside the viewport, zero
  page-level horizontal overflow, and Back restoration of the retained list.
- Existing reply, reply-all, forward-with-attachment, compose/send, draft,
  theme, pane-preference, and mobile composer checks continue to pass.

## Admission notes

Graphify is not applicable: the change is confined to one registered route,
one existing page/asset surface, and its focused tests. Direct route source,
browser behavior, and tests are the cheaper authoritative evidence.

Performance benchmarking is not warranted. The path replaces one JSON message
read with one HTML fragment message read; it does not add a second IMAP read,
storage path, or unbounded request. The vendored HTMX asset is 51,238 bytes
before transport compression and is served with `no-store` in this alpha
candidate, matching the existing asset policy.

The first cold review rejected a content-inspecting Trusted Types policy and a
duplicate hidden copy of the message body. The repaired policy admits only the
exact inert wrapper plus server marker, and the context template now reads the
already-rendered visible body. A later review also caught the swapped reader's
missing empty-state nodes and an accidental change to sanitized-HTML text
presentation; both were corrected before admission.
