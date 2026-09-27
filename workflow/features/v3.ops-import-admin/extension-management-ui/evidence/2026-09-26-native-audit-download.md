# Native audit attachment — bounded acceptance

## Accepted scope

Test-equipment increment on base `7c000229a28f104d198125df901c7727e68a2cae`.
Production is unchanged. The optional fifth browser-runner argument `audit`
checks the actual initial-instance audit attachment; four-argument navigation
selection remains available. This does not close the whole Extensions/B1 gate.

The real browser uses native Tab/Enter on the rendered link, application scripts
disabled and an injected cookie pair, not a bearer or live OIDC login. Chromium
saves the GUID-named file in private temporary storage. Checks cover expected
URL/suggested filename, physical file existence, received bytes, nonempty fixture
size, final newline and parseable JSONL. Event ID/action sequence, resource and
count match a separate SQL query, not the production exporter. Only size/count/
hash are retained; attachment contents and private credentials are not retained.

The 1 MiB check occurs after download; it is not a streaming or product/disk cap.
The initial fixture has one event and no configured secret. Cookie-string absence
is checked, not general configured-secret redaction.

## Review-discovered failure and correction

The first two independent reviews rejected a real equipment defect: a duplicate
download or signal during Browser.close could be swallowed after early PASS.
Process exit alone also did not guarantee completed stdio drainage.

The correction follows the Node v26.5.1 ChildProcess contract: exit records
termination; close resolves the bounded shutdown wait after process and stdio
closure. Immediately before synchronous proof publication, an audit interruption
or missing drainage forces FAIL and exit 1 with a fixed sanitized reason. Existing
cleanup remains. No await separates this final check from publication.

A 72-line controlled fixture executes the actual driver body and its handlers/
finally with substituted I/O. It is not a copied latch algorithm, VM security
boundary, module-loading check, real signal-delivery test or real deletion test.
Its waits are accelerated and process enumeration is stubbed.

| Controlled case | Old driver | Corrected driver |
|---|---|---|
| Normal completion | PASS | PASS |
| Duplicate during close | Incorrect PASS | FAIL / exit 1 |
| Signal during close | Incorrect PASS | FAIL / exit 1 |
| Duplicate after exit, before close | Incorrect PASS | FAIL / exit 1 |
| Exit without stdio close | Incorrect PASS | FAIL / exit 1 |

Regression assertions therefore exit 1 against the old driver and 0 against the
correction. All corrected cases also check private cleanup calls. In the red run,
the first failing gate assertion prevents later assertions for that case; those
later checks are not credited as executed red evidence.

## Actual application evidence

Raw development evidence:
`/home/linus/.artifacts/gotth-mail-live-browser-20260926/audit-download-first`.
Targets: Go 1.26.6, PostgreSQL 16.14/160014, Node 26.5.1 and Chromium
151.0.7922.71 with its normal sandbox. The existing admitted alpha.1 archive and
real runtimeMux fixture are reused; no archive rebuild or host trust change.

Final run3: PASS, 7.27 seconds, exit 0. Eighteen native Tabs then Enter initiate the
actual 493-byte, one-event attachment. Cookie-free inventory returns 401;
authenticated detail and audit return 200. Independent durable-state equality,
no non-GET/browser bearer/receiver traffic, and empty-runtime checks pass. Browser
exit is 0 with no descendants; namespace reports zero live processes/residual
paths. The physical attachment is validated before private cleanup removes it.

The original layout assertions report NOT_RUN in audit mode. No layout/lifecycle
rerun or wider acceptance is inferred. Corrected-driver real success and synthetic
fault evidence remain separate.

## Exact identities and verification

Frozen reviewed five-file source SHA-256:

```text
ed725a111851b401f663ff6158f07950a200bdff25449a5f041d09dcd0eb02c8  cmd/gotth-mail/extensions_browser_test.go
2b1913bcc17d728c49f207bcecfbc928ad81a338aaa8e747404d649e94a282de  scripts/extensions-browser-smoke.mjs
2b60163c33342770e78fb923788f5ed0da02c5e8e318e9368999ea9ea2c5e7fd  scripts/extensions-browser-smoke.test.mjs
e64a795c8152b78552ba4f7abca964e207683e85354d75aa93b90531279ff5da  scripts/extensions-browser-acceptance.sh
d1f78a2b49d97a18e275ea18926e0cd6fefcba9120544b57ca03088e45e46081  docs/CHANGELOG.md
```

Raw evidence SHA-256:

```text
47c8b7bbece4eba1930758aedbd1392055865c44b5b1afbd7defebac3389f766  late-red.log
820bc64d08889487e356e0ab2a194096c2334066d34c77c794ad19916be5687c  late-green.log
7e6e2a8637cec1125bc495b1c4af3aa11c45d3a9d3c231d95508530db3113d73  run3.log
fec860e37b02333cb0acfbdc2367767e26ac0c5c662eadc58f74b38e8e17f468  run3/browser/proof.json
c63f5f4a1aea272bfafc226a0b43b56c7651da81fddf4b8850d717b991cf34f2  downloaded attachment (removed)
7076176d94a00f87192426dad51c9e7e7acf3878d0e318d46560e65ff436dd5d  command test binary (removed)
68da3c355c2f0f2b36ba73963f2f2e2de69c5cb08dcac026d26eeee9cb60d6b4  build-info-latch.txt
```

Actual build metadata was captured while the binary existed and explicitly
records race instrumentation. Compile-latch exit 0; prior scoped vet exit 0 is
reused for identical Go input, not called a rerun. Formatting, syntax and diff
checks pass. The final synthetic green was rerun after a comment clarification
in its fixture; application-driver bytes did not change.

Reproduce on development:
- `node scripts/extensions-browser-smoke.test.mjs`
- Compile `./cmd/gotth-mail` with `GOMAXPROCS=4 go test -race -p=2 -c`, then
  `scripts/extensions-browser-acceptance.sh TEST_BINARY ALPHA1_ARCHIVE PG16_BIN NEW_EVIDENCE_DIR audit`.

The old driver is retained as `driver-before-late-latch.mjs`; historical
`final-source.sha256` does not describe the current driver. Current executable
inputs match `latch-source.sha256`. This later canonical Markdown record is the
only addition after the five-file freeze; no executable input is changed.

## Admission, accounting and remaining work

Fresh independent reviews `53f12c72-0d5a-4172-b8be-24c6d0bffd5f` and
`ad12307b-d1a0-40de-b36b-3aa99e992a98` returned PASS/CLEAN with the stated scope
constraints. They inspected source identities, contracts and raw evidence without
rerunning tests. The parent separately inspects this later canonical record;
those reports did not pre-approve it. The changelog retains its pre-admission
entry; this record supplies the final bounded disposition.

Exact inactive test binaries were removed after their metadata/hash/stat records
were retained. Required source/evidence remains 6,905 KiB/697 entries. Root
inodes remain 5,816,633 of 6,056,957 (97%); builds and task outputs used verified
/home ZFS/private temporary filesystems. Shared caches and unrelated state were
not cleaned. Performance N/A: test-only correctness work, no production or
speedup claim. Graph/context indexing N/A for this direct bounded closeout.

No all-field equivalence, nontrivial ordering permutation, configured-secret
redaction, empty/1000-boundary/error/cancel matrix, live OIDC, full keyboard/forms/
lifecycle/theme/AT, release or deployment admission follows. No workflow feature
is marked done. Continue the remaining browser and beta acceptance work.
