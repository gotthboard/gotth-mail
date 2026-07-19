# v4 containerized custom webmail UI smoke evidence

Status: custom GopherMailForge webmail shell is reachable in the repo-owned container topology. This does not claim Roundcube as the custom UI.

## Scope

Close the container reachability part of the custom webmail UI blocker without pretending the external Roundcube provider is the custom product UI.

## Implementation

- Added `GET /webmail` to the GopherMailForge API server.
- The route serves a minimal custom webmail shell with links/contract text for:
  - folder loading through `/api/v1/webmail/folders`;
  - message list/read/search through `/api/v1/webmail/messages`;
  - durable drafts through `/api/v1/webmail/drafts`;
  - conservative text-only rendering unless/until a real sanitizer/browser proof is admitted.
- Added `TestWebmailShellIsReachableWithoutRoundcube`.
- Added env-gated `TestLiveContainerWebmailShellReachable`.
- Added `scripts/containerized-webmail-ui-smoke.sh`, which starts the repo-owned Compose `gophermailforge` service and tests `/webmail` from the `test-runner` container.
- Added contract coverage for the smoke script and explicit test-runner rebuild behavior.

## Verification

- `go test -count=1 ./internal/api` passed.
- `scripts/containerized-webmail-ui-smoke.sh` is the container gate for this slice.

## Remaining blockers

- Real OpenPGP/MIME signing and exact-sender verification remain blocked; the UI shell does not bypass signing.
- Rich HTML rendering remains intentionally text-only until a sanitizer/browser proof is admitted.
