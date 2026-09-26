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

## Live candidate

- Release path:
  `/opt/gotth-mail-test/releases/dev-signed-out-shell-ca14f01-20260926T150503Z`.
- Runtime version: `dev`.
- Deployed control-plane image ID:
  `sha256:60dc99ec5c0040934a9d97efefed515e93954309f24a22c12e4669190332472f`.
- Retained archive SHA-256:
  `413e19742189633a8e6fcb3944273ea46f231fd22b78558d6c452a70621c65f1`.
- Real Chromium at 390 by 844 proved the signed-out state contains one bounded
  sign-in card, no rendered authenticated shell, no overflow, no page scroll,
  and the `dev` footer.
- All six containers are healthy, both managed services are active, and mail
  ports 25, 143, 465, 587, and 993 are externally reachable.
- Immediate rollback remains immutable `v1.0.0-alpha.2` at
  `/opt/gotth-mail-test/releases/v1.0.0-alpha.2-0bdb230`.

This candidate is not known-good until Danny confirms it on his phone.
