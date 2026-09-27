# Installed-extension browser audit download — 2026-09-26

Base: `69c0283038457a6a046256ab60d5bea3f563fec8`. Scoped route/anchor repair, not physical-browser or beta admission.

## Mechanism and boundaries

Ordinary cookie navigation previously reached the bearer-only audit API and returned401. The detail anchor now targets the dedicated GET `/admin/extensions/{id}/audit`. Existing bound-session/paired-cookie authentication and exact lowercase extension-resource `ops:admin` authorization precede protected registry/audit reads. Explicit Authorization retains precedence. The instance must exist in the Mail registry. No caller query overrides, new grants, API cookie fallback, constructor, service, identity, schema or runtime changes.

Existing SQL reader filters resource type and ID before timestamp DESC/id DESC LIMIT1000; existing recursive read-time redaction and JSONL exporter remain authoritative. Static NDJSON attachment, no-store/nosniff, empty200, sanitized route-local errors and GET-only405/AllowGET are covered. The UI says recent/up to1,000, not complete history. General bearer JSONL/CSV and cookie-only API denial remain unchanged.

At most1,000 rows does not bound SQL work, bytes, recursive processing or memory: existing reader/exporter materialize events and output. No invented byte cap, streaming or optimization claim. BoundSession checks enabled mailbox, not domain.enabled. Separate Mail DB is the product boundary; audit rows have no product column. Registry lookup followed by concurrent uninstall may still yield an authorized audit snapshot. Existing ignored JSON decode/encode errors and key-based redaction are not corruption repair or arbitrary secret scanning.

## Test-first and verification

Development native PostgreSQL16.14 (160014), cached Go1.26.6. Before production edits, actual runtimeMux followed the rendered link with valid cookies and real registry/audit SQL:401/text/plain, cmd-red exit1. Dedicated UI red also failed against the absent route. Tests later passed with durable SQL session/current-role fixtures, not mocked authentication truth. Runtime mounting uses an explicitly separate injected session-binding fixture; neither proves live OIDC login.

Covered: global-admin admission; revoked/expired/future/missing/mismatched sessions, disabled mailbox, removed/other-identity/restricted roles; exact resource authorizer and denial-before-registry access; explicit bearer precedence; fixed scope beforeLIMIT with1,201 newer unrelated rows; matching counts0/999/1000/1001/1200; independent ID/timestamp ordering and separate B export; direct legacy nested redaction; unchanged SQL registry/secrets/previews/sessions/roles/audit snapshots; repeated read consistency; methods, queries, conditional requests, installed absence and sanitized SQL/service failures. No runtime mutation call is introduced.

Initial implemented UI run failed one incorrect encoded-slash test expectation. Pinned Go routing source excludes decoded slash-only segments from a single wildcard: `%2f` falls to the unchanged prefix400; `a%2fb` reaches the new handler and returns404. Both final assertions remain. No router/prefix weakening was made; the initial failure and diagnostic logs are retained.

Recorded focused UI/cmd race, whole UI-package race, focused existing API compatibility and vet runs exit0. These are not whole cmd/API/full-repository or unchanged delivery-artifact reruns. Physical browser/no-JavaScript download remains unexecuted in this unit.

## Reviewed versus tested source

First review found false constant-cost registration comments. Parent corrected only those two comments, accounting for ServeMux conflict scans, lock waits and tree/index growth using symbolic delegated costs. Exact comparison to hashed frozen development files proved one ordinary-comment substitution per file; all other bytes remained unchanged. Final source hashes below were NOT recompiled after this correction. Tested extensions.go SHA was `49f7a5a886f86aff4aa088e78a0c3c59107b85c4a78a793f905b9504573276aa`; tested extensions_audit.go SHA was `3419a30b8e68a462f347cef4d3a9c756427f089a58b502a78080fb50abe61e7a`. Tests/spec are unchanged; changelog references were finalized.

Final reviewed identities:

```text
dba481e6f08dbc3ae5dfa9073af3c6e759e2430019e8ae5fdb67b3fb1df87e84  internal/httpui/extensions.go
c39be04b76da79197c21949e4b2d23ce6ad44ea4db308e3240e96a5387cf14c4  internal/httpui/extensions_audit.go
371f83226ecf4784eb9ce3004c7377400b08a6ccf6a4cf3c21aa44be00a05aea  internal/httpui/extensions_audit_test.go
92347bf5e1d916b8e310de913d99c387f791e1953d275fc138728e9d1afc975f  cmd/gotth-mail/extensions_audit_test.go
be56805a9b99e1512f1b4e03053dc524a4852dd2a1b3a4b6c7760534f7dbc1b4  docs/implementation/v3-ops-import-admin.md
be0d363c13399bb192ed14094a9783007d1b69777bd30c582e62cc452b88e0bd  docs/CHANGELOG.md
```

Initial handoff patch SHA33b53844febd137a91bc74b6bf86fe4184f76c4297bbd8a1f49bd28119e621f0 predates the comment/reference correction; it is not the final patch hash. Two fresh post-correction reviews `04d3facc-7615-402f-9ab4-fb25a572635c` and `e7b48e7e-dca4-4856-802a-9f47c2d4d5ce` returned CLEAN. The intermediate timed-out review supplied no verdict and is not counted. Canonical evidence requires separate parent inspection.

## Retained evidence and reproduction

Development root: `/home/linus/.artifacts/gotth-mail-audit-browser-20260926`. Source snapshot, logs, exits and build hash manifest retained; prior failures were not replaced.

| Log | Exit | SHA256 |
|---|---:|---|
| cmd-red.log | 1 | f0be91119647a824c5668714e83f2935838d76acdaaef7f25573c5a3a3db5584 |
| ui-red.log | 1 | f7c1716b0a31f0744735ef2839db066942f32890dd2a3ed28bfa8f07df325b86 |
| ui-green.log | 1 | af70d44847636ea70ecf8d47537c43efa73d89ce8aeb08941cf37f6b6ef1c388 |
| ui-debug.log | 1 | 35d648e47310194f4133179a5da4ec82c38e901d28d56a4922475584fc82dc60 |
| ui-final.log | 0 | a6c7cf9693b5678bd2e710ce4775bdff9cc4b33d88350acfce446755794f1440 |
| cmd-final.log | 0 | da3406b338b7d30010fcd4cf94eb8e0e18543a9447f42af4c7363b123cc1983b |
| ui-package-race.log | 0 | 48ae13c3b2df9f5f5fb8604bcdfbeeefb713f8c96d27c60dc4d1966a59dfcb19 |
| api-compatibility.log | 0 | 7154d920a9eea4250adbc7975a59bdc35d4bfaf4b4cd024068f7093a36344be4 |
| vet.log | 0 | e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 |

Build targeted test binaries with cached Go using GOMAXPROCS4, `go test -p=2 -c` for initial red and `go test -race -p=2 -c` for final UI/cmd/API. Execute in private bwrap user/PID/IPC/UTS/network namespaces with read-only root, private /tmp, native PG16 PATH, and both TMPDIR/GOTMPDIR=/tmp. New tests require `GOTTH_AUDIT_REQUIRE_PG16=1`; focused patterns are `TestExtensionAuditBrowser` and `TestExtensionAuditBrowserRuntimeLink`. Whole UI uses no filter and adds existing roundtrip/retention/update PG16 flags. Existing API compatibility selects `TestV3AuditRoutesUseSQLAuditStoreWhenConfigured`. Vet targets ./internal/httpui ./cmd/gotth-mail ./internal/api.

Six retained compile exit records are0. No separate debug-compile exit record exists; its runtime diagnostic does. Removed binaries cannot now be inspected for build metadata. Race flags rely on recorded compile commands/worker provenance, not fresh binary attestation; plain test logs alone do not prove compiler flags. Historical test-first ordering likewise is retained evidence, not a reenactment.

## Resource closeout and open gates

Seven inactive test binaries were hashed then removed; testpg/private PID namespace cleanup stopped temporary PG. Required source/evidence retained6,865,920 allocated bytes/681 entries. No browser was launched. Caches/output stayed /home ZFS/private tmpfs, no Docker/system/trust change or unrelated cleanup. Development root remained97% inode-used; host delta323,584 bytes/one inode was not task-attributed.

Physical native-browser/no-JS attachment flow, keyboard/320px/theme/status/accessibility, full live lifecycle/browser acceptance, identity/signing and overall beta remain open. No live OIDC/deployment, numerical coverage, new scan/iteration-error/disconnect matrix or concurrency guarantee is claimed. No merge, release or deployment admission.
