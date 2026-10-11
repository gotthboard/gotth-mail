# Recovery Phase B — owned qualification accepted; historical checkpoints retained

Final-candidate review closure: two fresh independent cold passes completed sequentially after the documentation correction. Parent inspected both and confirms the scoped Phase B acceptance below. Earlier retained-context confirmations are not counted as fresh passes. No Phase C/live/beta or deployment admission follows.

Current status: parent accepted Phase B owned qualification after two independent
reviews and independently confirmed documentation repair. No Phase C/live/beta
admission. See final acceptance below; earlier failures remain historical facts.

Historical status at 01:30UTC: BLOCKED / HANDOFF STOP, not B admission. Phase A remains parent-admitted. No
production file changed. Two new opt-in test files and ordered canonical proof
plan only; current source133 matches admitted A. No commit/push/delegation/live/C.

## Source and binary identity

Current service/CLI reused unchanged A native artifacts after SHA checks; no fresh
current build claim. Rebuilt BOTH binaries from unmodified immutable rollback
archive bb16776c83a8d6bb3b295b1582a10cfe3c4ce6c444f412727c6afd09e3020dcb, with
Go1.26.6/offline/GOMAXPROCS2/-p1 and independent source/tool/argv receipts. Separate
c365 legacy CLI is NEGATIVE control, never called rollback. Original26-file seal
and native proof seals preserved; historical archive vs26seal differs only in the
already documented final CHANGELOG closeout. Initial overstrict whole-archive seal
check failed there; no seal rewritten. Actual migrateSQL/validateMigrationLedger/
configureDatabaseFromEnv/BoundSession function bodies compare equal; whole sql.go
is NOT identical (A adds validator). Authz/issuer-loader files identical. Rollback
lacks projector/mapping/local doctor and MatchesBinding, only conditionally safe
with mappingsdisabled/sources0/nonoperatororphans0 maintained. No active Group claim.

## Actual successful core scenario (PG16.14)

core2: native exit0, one test PASS30.370s, no skip. Fresh phase-owned initdb cluster
using SCRAM for TCP AND local sockets, isolated admin plus maintenance/old/current/
rollback roles. Generated synthetic passwords in0700/0600 paths, absent from logs
and transferred proof. Real wrong password/user and selecting another privileged
role with old password denied; no memberships, ownership, superuser/BYPASSRLS or
SET ROLE/DDL/history-DELETE escape. Version/port/data_dir observed before role work.
Table-specific ACLs (not ALL); PG16 ledger UPDATE real capability, not lock-only.

Actual c365 changing revoke preview succeeds on0019 without ledger grant; exact
digest apply waits on held identity_refs row FOR UPDATE, actual DB/role/PID+
backend_start and blocker observed. NOLOGIN/CONNECT withdrawal rejects new old
connections, while separate old SELECT still succeeds. Only both inventoried owned
old backends terminated, blocker held; native CLI exit1, matching PG backend FATAL
termination and libpq bad-connection response, complete binding/source/history
snapshot unchanged. Timeout/bad digest/wrong query NOT counted. Real current
maintenance CLI withdraws3roles, preserves operatorUUID and intended revision2,
mappings/history/ledger, leaves zero enabled mappings/sources/nonoperatororphans.

Actual current and immutable rollback service OS processes start with fixture and
optional workers off; health+CLI operator no-op proof, distinct executable hashes,
old credentials and actual old CLI remain denied after each. Current principal denied
at rollback cutover. Owned services exit by explicit SIGINT (not graceful product
shutdown claim); sessions disappear before next pair/cut. No blanket PG termination.

Actual pg_dump at owned no-runtime-session cut, then pg_restore into newly created
empty recovery_b_restore. --no-owner --no-acl deliberately do NOT preserve SQL owner/
ACLs; original owners/ACLs are NOT claimed restored. Logical business authority,
history and ledger compare equal. Later disposable source sentinel absent in restored
backup demonstrates lost later data, not production restore authority.

## Full scenario remains FAIL

Five native scenario runs: core1 FAIL, core2 PASS, protocol FAIL, tls FAIL, full FAIL.
All manifests/source snapshots/logs/exits retained; each selected one actual test,
no native skip/zero selection. No PG17 run; no B qualification or full suite PASS.

- Initial core error oracle expected CLI termination text, but libpq returns driver:
  bad connection. Corrected only oracle to exact PG backend FATAL plus CLI cause.
  Initial5s PG shutdown deadline forced SIGKILL during~6s fsync; retained failure.
  Subsequent20s bound yielded actual PG exits0. No graceful cleanup fabrication.
- Protocol variant HTTP callback rejected by OIDC's HTTPS contract, before health.
  Replaced only fixture transport with ephemeral owned TLS frontend to real HTTP
  service plus process-local trusted test CA for actual provider TLS. No insecure
  certificate/authentication checks or host trust/proxy/config changes.
- TLS run omitted required CSRF cookie; current code adds actual callback CSRF cookie
  and hashed synthetic seeded-cookie bindings. Latest full still failed browser-role
  oracle401 where503 expected after actual signed OIDC callback/session and replay
  denial gates. Full native exit1/16.044s. No raw cookie/token/SQL payload logged.
  Failed subcase index/fixed reason was not logged. Seeded SQL now() timestamps use
  observed CDT default in timestamp-without-time-zone columns, while BoundSession
  compares UTC; plausible fixture expiry error, NOT confirmed product diagnosis.
  Do not alter production or weaken role oracle. Next diagnostic must identify exact
  subcase and safe fixed reason before a narrowly proven fixture correction.

Therefore full SCIM mutation, browser role allow/deny, actual current restart,
changing operator actions, daemon protocol, rollback protocol and PG17 confirmation
remain UNPROVEN despite executable assertions existing. Core start is not restart;
constructor or earlier in-process A checks do not close these missing B gates.
Actual core restore does not repair missing full qualification. Uninstrumented child
behavior is not parent coverage; no new coverage/race/full-scale claim.

## Prospective capacity stop and closure

Native retained task ~364.39MB, cache delta72.08MB, plus local/proof copies charged.
Final exact all-hop totals in ignored packet; planning forecast512MiB is not peak/
quota. Two further conservative full16+17 lanes plus cache/closeout exceed forecast:
stopped BEFORE another native lane. No failed fixture/history cleanup to fit; parent
must replan before continuation. Owner24GiB/file128MiB unchanged. Prior~2.30GiB+A264MiB,
renderer and old40MB fixture remain charged/untouched. Native root29%bytes/96%inodes,
5802927used unchanged; all new data/cache/source/temp offroot ZFS. Actual final child
caps134217728file/core1 captured for7 children; previous producer launcher limits
are separate inherited-contract evidence, not invented child observations.

All41 recorded native process PIDs and108 logged PG PIDs absent; owned PG/socket
listeners0. Five new stopped clusters/private configs retained, including initial
failed cluster; no data deletion. Parent evidence excludes private config contents,
contains safe hashes/connection identities; no same-OS-user credential-isolation
claim. Collector initially matched itself by root name; rejected check preserved,
scoped executable matcher corrected, no job failure relabeled. Later source/input/
command-parse/relative-seal errors documented in packet, no native test PASS inferred.

PostgreSQL authenticates credentials, NOT binaries: any holder of new DSN could run
an old binary. External host entrypoint/supervisor/credential distribution/ingress,
replacement prevention and live no-write interval remain Phase C assumptions/open.
Parent fresh reviews and bounded replan next. HANDOFF STOP; no self-start continuation.

## Authorized continuation — 2026-10-04 01:50UTC, still BLOCKED

Parent prospective TOTAL B forecast768MiB/continuationgrowth256MiB, original02:55hard
limit. Original6195B handoff/c121manifest/five native lanes remain immutable. No
binaries rebuilt, no production/ACL/schema/auth changes, no retained cluster reopened.

Diagnostic-only new PG16 lane diag FAIL11.789s established exact original401 cause:
fresh_callback503 with validUTC timestamps; existing_seeded401, fixed reason identity
session is invalid. Observed US/Central DB: seedexpires2026-10-03T21:43:38.476725Z
versus GoUTC2026-10-04T01:43:39.577501416Z, expires_gt_now=false. Only THEN changed
both Bsession seeds from SQLnow() to GoUTC bound parameters, past-created/future-expiry,
with explicit metadata/predicate assertions. No timezone override or status/CSRF
weakening. All session/cookie values remain undisclosed.

New utc16 full-route attempt FAIL23.267s, native1. It proves the narrow fix: all3
predicates true; fresh_callback503, existing_seeded503, ordinary_seeded403 with exact
fixed reasons. Real signedTLS callback/session/replay and self-service gates reached.
Next SCIM authenticated User GET500 (wrongtoken401 passed). PG17 unrun, no fullB PASS.

Bounded new-failure diagnosis (<3min) found a separate SCIM fixture contract defect:
bSeedProtocol hand-inserts version='v1', arbitrary JSON and no indexes. Pinned
SCIMv0.1.0 renderRecord requires a quoted canonical-content version, exact prepared
indexes and canonical bytes. v1 deterministically violates the version contract;
quoting v1 alone is not a fix. No contemporaneous PG permission error observed.
HTTP detail was not retained, so no claim of captured fixed SCIM reason. No product
bug/permission defect asserted. No grants raised or additional SCIM seed rewrite
performed under the timestamp/CSRF-only repair continuation. Parent must scope that
next fixture repair using the existing public SCIM construction contract, then
full16 before17. Assertions/statuses remain unchanged and latest failing source
is frozen. No new helper/environment campaign.

Continuation source/raw manifests/logs/exits, beforeimages and aggregate handoff in
identity-recovery/phase-b/continuation/. Both new clusters remain stopped/retained;
54 observed native/PG PIDs absent,14child actual capsfile128MiB/core1 verified. All
prior failures/partialsteps still charged. Current cause is missing SCIM fixture
qualification, not the original capacity stop; exact revised accounting in packet.
Parent review/replan next; no B/C admission or automatic continuation.

## SCIM repair continuation — 2026-10-04 02:15UTC, admission still BLOCKED

Narrow parent authority in continuation/parent-scim-disposition.md. Only Bsynthetic
SCIM seed repaired: pinned public NewRegistry/DefaultDefinitions/NewReconciler/
Reconcile -> SQLStore store-only preparation. Library creates opaqueID, canonical
bytes, content-derived tag and exact indexes. Captured ID by exact scope/type/
externalID/manager, linked exact preexisting mailbox/identity/issuer/subject; all
fixture GET/PATCH/mailbox references use that ID. No production, binary, grant,
expected response, auth/TLS or rollback change. Source audit of remaining SQL,
projection, operator, OIDC and daemon contracts recorded BEFORE native lane.

New unique scim16 full scenario PASS41.878s, native0; scim17 identical-source full
scenario PASS22.539s, native0. Actual16.14/17.10 independent versions, one test each,
no skip. Current + restarted-current + rollback each passed signedTLS/RS256/PKCE
OIDC/session/replay/browser503/503/403, token401/UserGET/PATCH/mailbox persistence;
real Postfix domain replies, oldcredential/CLI denials, changing operatorgrant/revoke,
owned dump/emptyrestore/ledger/history/businessstate/later-sentinel-loss all ran.
Native PASS is not PhaseB admission: resource collector detected actual core limits
unlimited/unlimited on ALL52 child receipts, instead of prior required1/1. Filecap
134217728 both remained. I omitted the outer core-limit wrapper when reusing run.sh;
the unchanged runner only sets filecap. Collector FAIL is material, not formatting.
No core file found in new lanes, but that is NOT enforced crash-output containment.
No retroactive caps or rerun relabel. Repeating two clusters would exceed remaining
768MiB cumulative forecast; stop for parent resource/retest disposition. No cleanup.

Raw functional PASS and collector/resource FAIL preserved separately under
phase-b/continuation/scim-repair/. 108 observed PIDs absent, owned listeners0; both
new clusters stopped/retained, previous7lanes untouched. Production133 unchanged,
finalGo matches both native runs; only documentation follows. Parent fresh reviews
and explicit cap/retest disposition remain before B admission; no PhaseC/live work.

## Final scoped parent acceptance — 2026-10-04

Capped full PG16.14/17.10 scenarios passed (31.076s/20.977s), with separate strict
collector exit0 and52 actual child limits core1:1/file134217728:134217728. Source
and binaries were unchanged; the prior unlimited-core runs remain resource FAIL.
The fail-closed launcher verifies limits before native probes. Full owned tests
cover authenticated legacy denial/termination, atomic withdrawal, current/restart/
conditional rollback pairs, real bound-session/browser-role/SCIM/daemon behavior
and isolated dump/restore. Provider exchange remains an owned TLS stub.

Both fresh reviews found one documentation blocker:4560 historical changelog lines
were lost during closeout. Parent restored the exact220221-byte suffix from the
intact archive, retaining the496-byte new entry. Both reviewers independently
confirmed the restoration, all571 source files and unchanged executable/native
inputs. Faulty images and all historical seals remain retained. This repair and
admission documentation require no native rerun; prior functional/cap conclusions
are reused evidence, not new executions. No mandatory residual finding remained.

Admission is ONLY this disposable qualification. Rollback requires disabled
mappings/sources0/nonoperator-orphans0 and intentionally lacks later projection/
mapping/local-doctor capabilities. PostgreSQL authenticates roles, not binaries;
a new-credential holder can run an old binary. Same-OS-user fixtures do not prove
external credential/entrypoint/supervisor/ingress isolation. Restore comparison is
11 enumerated logical business/history tables plus ledger, excludes SQL owners/
ACLs, and authorizes no live or post-write data-loss restore. Services stopped by
signal are not claimed graceful exit0. No child coverage/race/scale/SLO admission.

Cumulative B before small final local documents was883.30MiB against prospectively
replanned1024MiB, not peak or aggregate quota. All prior failures remain charged;
owner24GiB/per-file128MiB unchanged. Parent admission beforeimages/new manifest are
in cap-retest/parent-admission; native receipts remain in cap-retest/proof.
Phase C/external provider/deployment and broader feature/beta gates remain open.
