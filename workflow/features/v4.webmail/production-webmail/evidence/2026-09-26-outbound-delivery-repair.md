# Outbound delivery repair

Date: 2026-09-26 CDT

## Failure and traced mechanism

Three accepted submissions remained deferred under queue IDs
`4hsYmz0vDBz30Xb`, `4hsYpy6pdvz30XT`, and `4hsYr73763z30Xx`. The live error
was `Postfix delivery deferred: Postfix helper token file unavailable`.

The production Compose mount was present at the configured
`/run/secrets/postfix-helper-token` path and was deliberately owner-only:
mode `0400`, UID/GID `1000:1000`. The `gotth_policy` pipe was configured as
`user=nobody`, so Postfix executed it as UID/GID `65534:65534`; that process
could not read the file. The defect was therefore the generated production
execution identity, not a missing mount or guessed filesystem permission.

Two fail-closed deployment probes exposed additional Postfix contracts before
mail was allowed to leave:

- using `postdrop` as the pipe's primary group is rejected by Postfix because
  it is a privileged mail-system group;
- making `postdrop` supplementary is ineffective because pipe(8) deliberately
  clears supplementary groups.

The admitted design runs delivery as the token owner, UID/GID `1000:1000`,
with no queue group. It reads the owner-only credential and obtains queue
metadata through the already authenticated loopback helper. Only that root
helper executes `postqueue`/`postsuper`. Approved mail is handed to a
loopback-only Postfix listener and then uses Postfix's native MX transport.

## Source

- `ff51fd8d6e36debb605a3e3d05a02137e38c1c07` — guarded native outbound
  transport, token preflight, loopback reinjection, and production smoke
  coverage.
- `9834f7389a3f0ccb35e62d8045263ec56db3a66a` — rejected intermediate
  supplementary-group model; retained in history and as the immediate
  predeployment rollback snapshot.
- `5dd9a6ec0ca196f311cc9c37d29db4f7a91af948` — final loopback-helper queue
  inspection and exact UID/GID model.

Changed source surfaces across those commits:

- `build/production/Dockerfile`
- `cmd/gotth-mail-entrypoint/main.go` and tests
- `cmd/gotth-mail-health/main.go`
- `cmd/gotth-mail-postfix-gate/main.go` and tests
- `configs/production/postfix/environment`
- `configs/production/postfix/master.cf`
- `internal/postfixgate/inspector.go` and tests
- release architecture/implementation documents
- `scripts/production-runtime-smoke.sh`

No secret value was printed, rotated, or committed.

## Verification

Development-host results:

- focused entrypoint, Postfix gate, and HTTP inspector tests: PASS;
- the same focused packages under the race detector: PASS;
- `go vet ./...`: PASS;
- shell syntax and `git diff --check`: PASS;
- absent, wrong-path, unreadable-token, wrong-UID, and wrong-GID regressions:
  PASS;
- the broad Go run reached the existing temporary-PostgreSQL launcher/socket
  defect and timed out after connection-refused failures in unrelated SQL
  packages;
- the full production container smoke repeatedly stopped during fresh Rspamd
  SQLite initialization with `database is locked`, before reaching the
  Postfix assertion. A prior run reached the mail stack, while the final
  exact pipe/helper path was proved against the live production topology.

Live verification:

- image:
  `gotth-mail-responsive-postfix:dev-5dd9a6e`,
  `sha256:82b4ca622dd2a16576c75fd2af2f62589a15a6205ae069b5d19b27831ce82ab8`;
- source-state:
  `5a6261eb961cf815dec7a9b8b202d5f81c585fc340e016c61d675cc3e2f01865`;
- release path:
  `/opt/gotth-mail-test/releases/dev-outbound-5dd9a6e-20260926T180305Z`;
- immediate rollback:
  `/opt/gotth-mail-test/releases/dev-outbound-9834f73-20260926T175600Z`;
- all six containers healthy, deployment service and Caddy active, and ports
  25, 143, 465, 587, and 993 reachable;
- authenticated SMTP negotiated certificate-verified STARTTLS using
  `TLS_AES_256_GCM_SHA384`, authenticated, and accepted DATA;
- Dovecot delivered the local verification message and authenticated IMAPS
  found it in INBOX;
- a real Chromium run at `390x844` rendered one bounded signed-out card, no
  authenticated controls, `390px` document width, `844px` document height,
  and no horizontal or page scroll.

## Preserved queue disposition

One explicit flush at `2026-09-26T18:03:34Z` processed the original queue.
Each original ID completed the policy pipe with DSN `2.0.0` and was removed
only after the loopback Postfix listener accepted its replacement. The
original/replacement relation is unambiguous from the distinct message sizes
(the reinjection adds the same 169 bytes to each message):

- `4hsYmz0vDBz30Xb` (2556 bytes) -> `4hsb6G4gJTz30Y3` (2725 bytes): Microsoft
  `52.101.41.54` returned `250 2.6.0`, internal ID `2649994823502`;
- `4hsYpy6pdvz30XT` (2179 bytes) -> `4hsb6G4j9wz30Y5` (2348 bytes): Microsoft
  `52.101.42.18` returned `250 2.6.0`, internal ID `3100966388990`;
- `4hsYr73763z30Xx` (2182 bytes) -> `4hsb6G4ls7z30Xb` (2351 bytes): Microsoft
  `52.101.41.201` returned `250 2.6.0`, internal ID `108452219193284`.

All three replacement IDs then recorded `status=sent` and were removed. The
live Postfix queue is empty. This proves external SMTP acceptance by the
`dannyhunn.net` Microsoft protection service.

## User acceptance and known-good reference

At `2026-09-26T18:13:24Z`, Danny confirmed, "I got the mail." That closes the
inbox-placement acceptance gap for this repair. The exact known-good outbound
candidate is implementation commit
`5dd9a6ec0ca196f311cc9c37d29db4f7a91af948`, image
`sha256:82b4ca622dd2a16576c75fd2af2f62589a15a6205ae069b5d19b27831ce82ab8`,
and release path
`/opt/gotth-mail-test/releases/dev-outbound-5dd9a6e-20260926T180305Z`.
No rebuild, restart, tag movement, or release promotion was performed while
recording this acceptance.

## Remaining deliverability boundary

The server PTR is still generic Linode and DKIM is not yet published. Danny's
receipt proves this message path worked; it does not remove those broader
deliverability defects or guarantee placement at other providers.
