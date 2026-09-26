# Signed-out mailbox shell repair

Date: 2026-09-26 CDT

## Failure

An unauthenticated or expired Web Mail session returned `401`, but the browser
only changed the account label and status text. Authenticated mail controls,
search, folders, quota, and empty reading panes remained rendered. On a phone
this looked like a broken mailbox instead of a signed-out state.

## Repair

- The document now starts in an explicit loading state.
- Authenticated mailbox controls are admitted only after the identity request
  succeeds.
- A `401` clears rendered mailbox state, closes mail dialogs, and replaces the
  mailbox shell with one bounded sign-in card.
- Theme control, product identity, the canonical footer, and the existing OIDC
  redirect remain available while signed out.

No OIDC, authorization, mailbox, transport, DNS, storage, or release-tag
contract changed.

## Verification

- Implementation commit:
  `ca14f0117764cd8f19c88a55cae4fcd906d3f8a3`.
- The real-Chromium regression failed before the repair because the session
  state never became signed out and the authenticated shell stayed visible.
- `go test -p=1 ./internal/api -run
  'TestWebmailShellIsReachableWithoutRoundcube|TestWebmailFooterEscapesReleaseIdentity'
  -count=1`: PASS.
- The same focused API tests under `-race`: PASS.
- `go vet ./...`: PASS.
- `node --check scripts/webmail-browser-smoke.mjs`: PASS.
- The repo-owned real-Chromium smoke: PASS. It covers the signed-out 390 by 844
  state plus the existing authenticated desktop, tablet, phone, HTMX reader,
  Back, compose/send, draft, theme, and pane-preference paths.
- `git diff --check -- .`: PASS.

## Full-suite coverage gap

The broad `go test ./...` gate could not complete on `development` because the
existing PostgreSQL fixture constructs Unix-socket paths from full Go test
names. Three paths were 111 to 114 bytes, exceeding Linux `sockaddr_un.sun_path`
capacity. PostgreSQL exited before listening and the harness reported only
`connection refused`. A shorter-name SQL migration fixture and the formerly
failing long-name fixture both passed when their generated socket paths fit.

That harness defect predates and is unrelated to this presentation-only
change. It was not folded into this patch. The relevant API, race, static, and
real-browser gates above are green.

## Release discipline

`v1.0.0-alpha.2` remains immutable. Any deployment of this repair is an
untagged `dev` candidate. If the live candidate is confirmed, the next honest
release identity is `v1.0.0-alpha.3`.
