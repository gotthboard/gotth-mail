# Swapped reader placeholder visibility repair

Date: 2026-09-21 CDT

## Failure

Danny's live phone screenshot showed the selected message beneath a large
`Select a message` placeholder. HTMX had made the correct fragment request and
swapped the reader target, but the fragment's `hidden` empty-state node still
rendered. The author rule `.empty-state { display: grid }` outranked the user
agent's `[hidden] { display: none }` rule.

The earlier browser check asserted only the DOM `hidden` property. That was
garbage evidence for a rendering defect: the property was true while the node
still owned a visible layout box.

## Repair

- Added the explicit author-level `[hidden]{display:none!important}` contract.
- Kept the HTMX route, target, swap mode, fragment contents, and responsive
  navigation state unchanged.
- Strengthened the browser regression to require computed `display: none` and
  zero client rectangles for the placeholder, and a visible layout rectangle
  for the message reader.

No authentication, mailbox authorization, CSRF enforcement, IMAP mutation,
SMTP submission, identity state, DNS state, or immutable release tag changed.

## Verification

- `go test ./internal/api`: PASS.
- Focused `go test -race` for Web Mail API/shell/draft paths: PASS.
- `node --check scripts/webmail-browser-smoke.mjs`: PASS.
- Repo-owned real-Chromium desktop/tablet/phone smoke: PASS.
- Authenticated live Chromium at 390 by 844 CSS pixels proved:
  - `data-mobile-view=reader`;
  - one message-fragment request;
  - the placeholder has `display: none` and zero layout rectangles;
  - the message has one rendered layout rectangle;
  - the list is hidden and the reader spans exactly 0 through 390 pixels;
  - `scrollY=0` and document width equals viewport width;
  - Back restores the retained message list, selected row, and keyboard focus.
- All six containers are healthy; Caddy and the deployment unit are active;
  ports 25, 143, 465, 587, and 993 remain reachable.

## Live candidate

- Source commit: `0bdb230de53a8a819851a16d190cf5c15d0f47f3`.
- Source-state SHA-256:
  `4dcaf989a109e1d5bf67768bc390288390b4611920aba7d17c7170da34b41592`.
- Control-plane image:
  `sha256:9448ce7c669fe51e98e28394383ec0582a0d0018eb480abb8bda2446443e8535`.
- Image archive SHA-256:
  `16c88a1df836c0c443bd58a29b16b1468af6fc717b1e2ced0629d478e7e53934`.
- Release path:
  `/opt/gotth-mail-test/releases/dev-reader-hidden-fix-0bdb230-20260922T030000Z`.
- Immediate rollback:
  `/opt/gotth-mail-test/releases/dev-htmx-reader-74717b8-20260922T023920Z`.

The footer remains `Version: dev`. This is a corrected development candidate,
not a rewrite of immutable `v1.0.0-alpha.1`.
