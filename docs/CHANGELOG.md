# Changelog

## Unreleased

### 2026-10-08 00:32 UTC — Implement Unit 2 A1 outbound authority foundation

Commit: uncommitted detached staging at c3654450a2dbe193b6e3cb745aded5e295db5ced; no commit authorized.

Affected: exact migration 0021 registration/parity, database startup credential separation and current-schema validation, migration-authority bootstrap scripts, production environment allowlists, focused store/startup tests, and this changelog.

Explanation: registers the immutable 21,724-byte outbound-authority migration at index 19 with SHA-256 dd72b1a6140ff76799e9febbe7d81407c54dff21ad81d90633d2acef303d785b. Startup now requires a dedicated migration credential, proves the migrator/schema-owner identities, runs the atomic migration on a one-connection pool, requires successful close, then opens the app pool and runs actual read-only ValidateCurrentSQL before database-backed service wiring. Exact-ledger fresh and sealed-0020 upgrade bootstrap scripts preserve the current app DML matrix while narrowing ownership and ledger authority. No A2 configuration/API, writer conversion, restore, backup-version, queue-protocol, scheduler, or validator behavior is included.

Correction: fresh and upgrade bootstraps now validate every pre-existing authority role, membership option, and relevant role/database setting before the first mutation. The fresh runtime fixture starts with a distinct installer and no product roles, executes the exact shipped principal/bootstrap sequence, and the upgrade fixture migrates through 0020 as the actual legacy login before the passwordless/SCRAM rename. Live tests cover all seven LOGIN/NOLOGIN collisions, privileged attributes, forbidden memberships/settings, app/legacy conflict, byte-preserved SCRAM, passwordless rename, MD5 zero-drift refusal, old-binary refusal, and NOLOGIN capability roles. The root Dockerfile is restored to the admitted Unit 1 bytes and excluded from A1.

Verification: focused local formatting/unit/static gates and a raw attributable PostgreSQL 17.10 affected-eight receipt are recorded in the Unit 2 A1 correction handoff; production runtime remains a source-deferred deployment gate, and workflow state remains unchanged and is not marked DONE.

### 2026-10-07 12:38 UTC — Prove retrying transport policy bypass RED

Commit: uncommitted detached staging at c3654450a2dbe193b6e3cb745aded5e295db5ced; no commit authorized.

Affected: v1 and release 1.0 outbound policy/forwarding PRD, architecture and implementation docs; outbound exact-sender workflow note; containerized retry topology smoke.

Explanation: two-container internal-bridge RED proves the current private-10027/content-filter topology creates queue B after one policy allow, then lets stock smtp retry queue B after policy revocation without a fresh policy call. Requirements now reject the second-queue retry bypass and freeze the thin final delivery-agent gate: fail-closed current-policy check before external DNS/connect for every qmgr request, defer on outage, two-phase verified hold on current forbiddance, and deliver_pass delegation to stock smtp on allow. The gate neither reinjects nor implements SMTP; the final Postfix queue remains sole post-bind body custody. Contracts bind the immutable complete original final-envelope recipient/provenance set, require every request to evaluate that set, and use the configured local forwarding identity for non-null envelope/DSN handling while null triggers remain bounce-suppressed. No production code/config/migration/Postfix patch was made.

Verification: development smoke at /tank/development/linus/artifacts/gotth-mail-retrying-transport-first-slice-20261007T1335Z exited expected RED. Queue A 4j0CN64kc7zpFdD != queue B 4j0CN86T5CzpFdK; policy allow count stayed 1; remote DATA returned 451 then, after revoke and flush, 250 with identical remote hashes 7e62e5832d9a333f9fc758553fcaf75885511641af5668d385c60a982ce22dcf and Message-ID <retry-transport-red@example.test>; cleanup removed both containers and the internal network. Parent closeout restored the full admitted changelog after the staged writer accidentally rewrote from a stale subset; the truncated bytes are retained in scoped scratch and no historical entry was edited.

### 2026-10-05 04:20 UTC — Repair multipart encoded-limit route

Commit: uncommitted detached staging at c3654450a2dbe193b6e3cb745aded5e295db5ced; no commit authorized.

Affected: webmail MIME multipart parsing, encoded-limit regression tests, implementation notes, outbound unit notes, workflow event log and this changelog.

Explanation: cold review found multipart.NextPart predecodes quoted-printable children and hides their transfer header before the encoded-octet limiter. Multipart traversal now uses raw parts so readMIMEPart applies the existing encoded and decoded limits uniformly. Size constants, MaxForwardOriginalBytes, forwarding transport, identity, live SMTP and beta scope remain unchanged.

Verification: pending native RED/GREEN/full-webmail evidence in this unit.

### 2026-10-04 12:25 UTC — Start MIME encoded-limit repair

Commit: uncommitted detached staging at c3654450a2dbe193b6e3cb745aded5e295db5ced; no commit authorized.

Affected: v1 mail-core forwarding contracts, outbound exact-sender unit notes,
webmail MIME parser tests/code, workflow event log and this changelog.

Explanation: bounded unit to prove and repair encoded MIME parts whose base64 or
quoted-printable prefix can decode cleanly after the encoded input has crossed
the existing part limit. The decoded 25MiB cap, MaxForwardOriginalBytes and
existing 50MiB inbound capability remain unchanged; full-size forwarding and
native retry enforcement stay open.

Verification: pending RED/GREEN in this unit.


### 2026-10-04 10:27 UTC — Focus outbound provenance equality recovery

Commit: uncommitted detached staging at c3654450a2dbe193b6e3cb745aded5e295db5ced; no commit authorized.

Affected: v1 mail-core contracts, outbound and Group workflow notes, workflow
active selector, outbound admission regression tests and minimal queue-time
provenance guard.

Explanation: narrowed recovery for equal original/final queue deliveries. A
loaded alias or catch-all root must not be treated as terminal delivery merely
because the final address equals the original; genuine direct leaves keep the
cheap path. The601-file identity composition is parent-admitted; the broader
Group feature remains incomplete and is not marked DONE.

Verification: development PG16.14 focused admission test recorded RED on
unchanged production, then GREEN after the minimal guard. Full package, race,
caller, static and admission-review gates remain required and unrun here.

### 2026-10-04 04:56 UTC — Integrate admitted identity components with UI/signing

Commit: uncommitted detached staging at c3654450a2dbe193b6e3cb745aded5e295db5ced; no commit authorized.

Affected: accepted identity69 paths (v2 contracts/checkpoints, runtime/store/authn/
rolebinding/projection/SCIM/API/ops and service/CLI), workflow, Group-role README,
notification_env_test.go, one API protected-UI seam test and this changelog.
Preserve both notification doctor/parity and explicit0644 fixture assertions.
All signing/UI source remains exact outside the declared test overlap.

Verify accepted source seals/modes/pathsets and unchanged133 identity production
inputs before import, contracts before plan/code, full ordered history and exact
restored suffix. New bounded PG16/17, race, vet/build and exact candidate browser
results are recorded in the parent component-integration-identity packet; this
entry is not an admission or full recovery/beta claim. One test-only SQL session
through protected UI seam covers current issuer, Group withdrawal, independent
operator preservation and domain non-escalation without changing product policy.
Earlier original-I recovery is historical, not final merged-artifact qualification.
No identity-provider/live/SMTP-caller/B5/deployment or publication changes.

### 2026-10-04 04:47 UTC — Admit scoped UI and signing-component integration

Commit: current commit; hash assigned by Git after commit

Affected files:
- workflow/features/release.1-0/outbound-exact-sender/README.md
- docs/CHANGELOG.md

Explanation: Record two sequential fresh independent PASS reviews of the
554-file detached component candidate, preserving accepted originals and all
historical changelog content. Clarify that absent workflow tooling is a disclosed
limitation, not an invented checker result or a workflow DONE transition.

Verification:41 normal,41 race and3 PostgreSQL17 selected cases; scoped vet/builds;
one fresh command-test build and two native permissions browser passes. The
second run directly observed the owned SQL server and required limits. Parent
verified the exact two-document closeout and unchanged executable inputs;
applicable evidence is reused, not rerun for this prose.

Non-goals: identity integration, production forwarding caller/final SMTP signing,
full-suite/live/performance/beta completion, branch promotion or deployment.

### 2026-10-04 03:30 UTC — Stage accepted signing components with accepted UI

Commit: uncommitted detached staging at c3654450a2dbe193b6e3cb745aded5e295db5ced; no commit authorized.

Affected: v1 PRD/architecture/spec; outbound feature README/evidence;
internal/webmail/forward_mime.go, forward_mime_test.go, runtime.go and public
testdata; internal/notifyruntime/email_config.go and email_config_test.go;
workflow.toml and this changelog. Exactly the accepted S15 paths are imported
or semantically composed onto the exact accepted U547 snapshot.

Preserve accepted UI code/templates/assets/authority tests and full historical
changelog entries. Only the outbound component integration is active; UI remains
incomplete and beta planned. Contracts and bounded plan precede code.
Verification: exact seed/hash/mode/source-set and complete history oracles;
scoped development checks and remaining exact-artifact/browser gates are recorded
in the parent component-integration-signing packet. This is not an admission
or independent-review claim; two fresh parent reviews remain required.

No identity import, F3 production caller, SMTP/key/custody/schema redesign,
B5/full-size transport completion, beta entry, publication or deployment.

### 2026-10-04 02:15UTC — B SCIM fixture repair; functional PASS, cap BLOCKER

Pinned public reconciliation replaces invalid synthetic SCIM records; generated
opaque IDs used consistently. Full PG16/17 native scenarios pass with unchanged
production/binaries/ACLs. Resource qualification fails: outer launch omitted the
core1 limit and52child receipts show unlimited cores. Native PASS is not B admission.
All9lanes preserved; parent resource/retest decision needed, no live/PhaseC authority.

### 2026-10-04 01:50UTC — Recovery B diagnostic continuation, partial

Observed US/Central seeded-session expiry mismatch before fixing only Btest seeds
to bound UTC timestamps. Actual current browser-role subcases now pass503/503/403;
full PG16 next fails SCIM GET against invalid hand-minted fixture version. No
production/ACL edits, PG17 unrun. Original five lanes and both continuation FAILs
retained; no B admission. See the appended Phase B checkpoint and continuation packet.

### 2026-10-04 01:30UTC — Partial recovery Phase B owned qualification

Uncommitted; same feature. Adds two opt-in native qualification test files and
PRD/architecture/spec/feature proof plan. No production changes. Rebuilt immutable
compatible service+CLI and separate legacy negative CLI; current A binaries reused.
Authenticated PG16 core fence/pair-start/restore passed; full protocol scenario FAIL,
PG17 unrun. Prospective capacity stop before remaining lanes; retained all failures.
See identity-recovery-phase-b-checkpoint-2026-10-04.md. No live/Phase C authority.

### 2026-10-04 — Recovery Phase A local atomic Group withdrawal

Uncommitted checkpoint, pending independent implementation admission. Adds closed
confirmed all-scope recovery CLI, read-only current-ledger validator and one
namespace/RLS-protected atomic withdrawal preserving operator origins/history.
Native PG16/17 least-privilege, ordering, rollback and real CLI evidence retained.
No live fence/compatible binary/restore admission; Phase B/C remain unassigned/open.
See identity-recovery-phase-a-checkpoint-2026-10-04.md.

### 2026-10-03 — Admit the notification binary-key repair

Commit: uncommitted closeout; no commit created

Affected: notification repair evidence, outbound-exact-sender README and this
changelog. Two fresh independent reviews passed. Record scoped admission using
unchanged tested executable inputs; native checks are reused, not rerun.
No global B5, full-beta, publication or deployment completion is claimed.

### 2026-10-03 07:08 CDT — Preserve notification binary signing-key packets

Commit: uncommitted bounded repair on c3654450a2dbe193b6e3cb745aded5e295db5ced;
no commit authorized; identifier pending parent admission.

Affected: internal/notifyruntime/email_config.go and email_config_test.go;
outbound-exact-sender feature README/evidence and this changelog.

Read raw binary OpenPGP bytes without text trimming; keep armor detection and
text decoding unchanged. Preserve existing fingerprint, lifecycle and protected
file checks. Promote the fixed public synthetic whitespace-ending P256 fixture
regression through the actual loader, configured constructor and resolve/sign/
verify. Raw single and duplicate counts, armor controls and mode0644 denial are
independent oracles; no random key generation or SMTP submission.

Actual promoted test RED exit1 (0.025s), GREEN exit0 (0.030s). Final development
Go1.26.6 selected22 pure email tests normal1.473s/race3.586s and package vet pass;
SQL recorder explicitly excluded, unrelated project/live suites not run.
Changed reader100% and containing loader90.3% coverage; selected package31.7%.
Snapshot a5f2ae5bc9cb29646f08892862bb13a0ea21e70f2b79401537fb3d839f44e37e.
This changes a byte-slice view, not buffering architecture; no speedup claim or
performance campaign. F3 admission/history, identity work and global B5 state
unchanged. Repair awaits two fresh independent reviews; no deployment.

### 2026-10-03 06:03 CDT — Admit the bounded forwarding component

Commit: uncommitted closeout; no commit created

Affected: outbound-exact-sender feature README/evidence and this changelog.
Two fresh independent revision2 reviews passed. Record scoped F3 admission,
unchanged tested executable inputs and reused checks, with SQL/live exclusions
and resource variance preserved. No final-relay, DSN/retry, full50MiB, whole-beta
or deployment completion is claimed. Docs-only diff/source checks passed.

### 2026-10-03 05:44 CDT — Correct two forwarding admission defects

Commit: uncommitted revision2 of base c3654450a2dbe193b6e3cb745aded5e295db5ced;
commit identifier pending parent admission (no commit authorized).

Affected: internal/webmail/forward_mime.go, forward_mime_test.go, runtime.go,
testdata/synthetic-whitespace.pgp and testdata/README.md; implementation spec,
feature README and this changelog. Earlier revision1 evidence remains historical.

Reject malformed forwarding Message-ID before resolution with a local bounded
RFC5322 dot-atom grammar; preserve existing shared parser behavior. Preserve raw
binary key packets in the runtime loader, trimming only for armor detection and
decoding. A fixed PUBLIC SYNTHETIC P256 fixture proves trimming one signature
byte changes two readable entities into one, causing old Build to sign with an
ambiguous keyring. This reproduces the predicted path, not the unretained random
bytes of historical green2. No broader partial-parser behavior is changed.

Native focused tests first failed on malformed-ID signed output, duplicate-key
signed output, and valid binary-single rejection; corrected focused run passed.
Source snapshot1ba147d579207f1eb051b4c85d1beaaafd7c2c8e5501b08ddbee1b51c78b96af:
webmail normal8.259s/race28.347s, notify email family normal1.195s/race2.515s,
and both-package vet passed. Seven webmail SQL tests excluded; three live tests
skipped. Notify tests select only21 pure email cases, SQL explicitly excluded.
Build95.7%, ID validator100%, loader83.3%, package69.7% coverage. Small diagnostic
benchmark repeated; boundary197.0–239.0ms/~160.52MB allocated, no speedup claim.
Conservative full-cache retained accounting reached~516MiB, above512MiB planning
target; this overcounts preexisting cache and is not a measured physical peak.
No owner limit relaxed; no cleanup/history deletion to make the ledger look smaller.
No caller wiring, workflow completion, B5 completion, commit or deployment.

### 2026-10-03 05:00 CDT — Bounded exact-sender forwarding preparation

Commit: current commit; hash assigned by Git after commit

Affected: v1 mail-core PRD/architecture/spec, workflow.toml,
workflow/features/release.1-0/outbound-exact-sender/README.md,
internal/webmail/forward_mime.go and forward_mime_test.go, this changelog.

Specify owner-approved local signed forwarding with opaque untouched capture;
compose existing lifecycle/sign/verify APIs without SMTP side effects. Reprioritize
workflow without marking the frozen accepted UI checkpoint complete.

Verification: compile RED before implementation, then real crypto/lifecycle and
opaque-byte tests GREEN. Final development Go1.26.6 package normal (7.979s),
race (25.990s), vet and three-sample allocation benchmarks passed; seven SQL
tests excluded and three live tests skipped without configuration. Build method
coverage95.7% (three unreachable owned-buffer MIME error returns); package69.4%.
Input cap19,156,674B and output cap27,525,120B are component-only. Boundary
allocation about160.52MB/op is explicit, not streaming or deployment admission.
Source snapshot aaa0a61b2d0f182443f6e92b8cac91b137270ce083860283fdfdcfe2d5c103a2.
Existing signer emits LF armor; only this component normalizes loneLF before
verification. Shared builder/crypto production behavior is unchanged.

No workflow-check PASS, gate integration, full50MiB capability, provenance,
DSN/retry completion, production key selection or beta completion is claimed.
Independent reviews and caller integration remain required.

### 2026-10-03 — Align normal-detail native theme test with admitted links

Test-only one-literal #permissions suffix in existing exact theme selector; no
production or canonical runner change. Preserved real selector RED, then one reused-
binary PG16/Chromium153 GREEN:12theme/reflow/form states at320/1280, native Tab/Enter,
0mutation and clean drain. Scoped evidence in feature permissions-pagination record;
parent review pending, not whole-UI/browser-floor/live-identity admission. No build,
commit, publication or deployment. Precisely authorized private runner enforces the
existing GOMAX2/512MiB temporary-filesystem limits; original preparation block retained.

### 2026-10-03 — Permissions MVP independent admission and closeout

Two independent CLEAN final reviews and parent admission accept PERM-01..06;
no product fix required. Counts/link and25-total-entry native detail pager retain
full authority/forms/recovery semantics. Existing PG16/17, focused race, generation
and one Chromium no-JS proof reused, not rerun. Failures/skips/coverage/engine limits
remain explicit in feature evidence/2026-10-03-permissions-pagination.md.
Owner40075 provisional performance acceptance stands; no new benchmark claim.
Only README, this changelog and one evidence record changed in closeout. Whole UI
remains in_progress: historical dependency bridges, named accessibility/floor and
live-identity/image/target claim gaps plus final whole-UI admission are not closed.
No commit/publication/deployment or other-beta rollover.

### 2026-10-03 — Permissions readability MVP implementation (uncommitted)

Commit: not created; independent final reviews and parent admission pending.

Add a private bounded GET parser and checked combined25-entry borrowed window;
replace inventory grant-name expansion with three counts and View permissions;
render ordinary detail Previous/Next/theme links. Preserve full update inputs,
all existing approval diffs, POST/ActionURL/CSRF/confirmation, recovery/terminal,
service/API/DB and production JavaScript. Regenerate existing inventory/detail pairs;
no new renderer, schema, quota, search/filter or permissions policy. Update only
related tests and one existing native browser fixture/driver mode.

Affected: internal/httpui/extensions_permissions_page{,_test}.go,
extensions_permissions_ui_test.go, extensions.go, extensions_inventory.go,
extensions_inventory_test.go, existing inventory/detail templ/generated Go and
inventory.css; cmd/gotth-mail/extensions{,_pagination}_browser_test.go;
scripts/extensions-{browser-acceptance.sh,pagination-browser.mjs}; the five PERM
contract/evidence documents. Detail CSS and all authority-bearing form bodies remain
unchanged. Scope remains readability, not complete detail/DB/memory boundedness.

Verification: genuine helper compile RED then34PASS; routed/component behavioral
RED37/35/2 then37PASS; pinned write/write/check identical. HTTPUI PG16/PG17 each
316RUN/314PASS/2existingSKIP; vet0; final focused PG16/PG17/race each38PASS. Parser/URL
helpers100% statement coverage; window95.8% (safe-slice overflow guard not forged).
One real Chromium153 no-JS keyboard/history/theme workflow:78 permissions across
25/25/25/3, complete form inputs,0browser mutations/bearers/SQL/runtime activity and
clean drain. All setup/selector/stale-assertion/oracle failures preserved and scoped;
no false credit for the zero-exit stage that ran no tests. Test-only final assertions
use source-dependency bridges rather than another browser or blanket rerun.

Evidence: .artifacts/gotth-mail-permissions-pagination-mvp-20261003/implementation.
No measured speedup, whole-UI/beta admission, commit, push or deployment claim.

### 2026-10-03 03:01 UTC — Read-only Permissions MVP contracts (uncommitted)

Commit: not created; contract-only working-tree change, parent review pending.

Affected files: docs/prd/PRD-v3-ops-import-admin.md;
docs/architecture/v3-ops-import-admin.md; docs/implementation/v3-ops-import-admin.md;
workflow/features/v3.ops-import-admin/extension-management-ui/README.md;
docs/CHANGELOG.md.

Owner40081 approves smaller40080 scope: replace inventory permission-name expansion
with three counts and an existing-detail link; ONE readonly25-total-entry Permissions
pager. Specify category/stored order, safe GET page grammar/arithmetic and precedence,
empty/beyond-end states, native/theme navigation and recovery-only exception. Preserve
complete update inputs/approval diffs and all mutation authority; no API/schema/quota,
JS, renderer pair or recovery bypass. Record finite test-first/generation/affected-
checks/one-browser plan. Owner40075's provisional performance acceptance does not
prove missing metrics and does not restart held1152-study work.

Verification for this unit: source-informed contract review, five-file delta and
543-baseline/unrelated-WIP identity checks, git diff --check; no code, tests, generated
assets, builds or native/remote work. Runtime correctness and independent final
admission remain pending. This improves intended readability only; full forms,
diffs, status/configuration surfaces and backend materialization remain outside
MVP and do not acquire HTML/DB/memory bounds or whole-UI completion claims.

### 2026-10-03 21:57 UTC — Add local durable identity doctor diagnostics

Commit: uncommitted development checkpoint; no commit created.

Configured local doctor reads existing role mappings/typed Groups/domains under
protected CurrentIssuer in a bounded read-only snapshot. It separates local
health from artifact consistency and external live proof, and exposes tuples
only through explicit local details. API/monitor/command summaries are fixed and
redacted; the existing identity check key is preserved. No-config CLI behavior
and report-failure exit0 remain. Configured CLI does not pretend to inspect a
deployed webmail/daemon runtime. No grants, schema, renderer or live-state changes.
See identity-local-doctor-checkpoint-2026-10-03.md and ignored native evidence;
independent parent review/external proof/full feature admission remain open.

### 2026-10-03 20:08 UTC — Extend durable Group mapping to all existing roles

Commit: uncommitted development checkpoint; no commit created

Affected: roleprojection eligibility/reconciliation, rolebinding GroupService,
group-role CLI/parser/help, all-role service/CLI tests, canonical identity docs.

Authorized IDP-GROUP-007 behavior change: global_admin (NULL target domain) and
scoped_domain_access join the admitted domain_manager path. Keys, source guards,
audits and full preview diffs carry actual role and nullable target; plan schema
v2 invalidates v1 confirmations. Global CLI must omit --domain; scoped roles
require an exact known enabled target for admit. No migration or authz action
change; common mailbox/domain/issuer guards and mailbox-only API actors remain.
Historical valid-global rejection is replaced by an actual unknown-role corruption
control; global-with-domain rejection remains a shape guard. Real RED and native
GREEN receipts are retained in the all-role checkpoint. Final verification and
independent parent admission are separate; profile/doctor/live proof and beta
completion remain open.

### 2026-10-03 — Checkpoint confirmed Group-mapping service and CLI

Commit: uncommitted development checkpoint; no commit created

Affected: internal/rolebinding/group_mapping*.go; internal/roleprojection/
{projection,eligibility}.go; cmd/gotth-mailctl/{main,group_role,group_role_test}.go;
internal/api/group_mapping_cli_test.go; Group-role README and mapping evidence.

After parent admission of the projection/caller phase, add domain_manager-only
identity group-role preview|apply with closed admit/disable flags. Protected
LoadIssuer supplies authority; request issuer/BaseURL cannot override it. Actor-
derived scope and typed live Group/exact enabled domain gate admission. Retired
opaque Groups cannot be rebound through another domain/issuer tuple. Recovery
disable works without current issuer/live Group/enabled domain; malformed protected
files still fail closed. No-op writes nothing and never reconciles opportunistically.

Preview is pure read-only REPEATABLE READ, with a versioned fingerprint over exact
authority, mapping, Group/domain, members, identity ownership and origin state.
SERIALIZABLE apply rechecks confirmation, changes mapping and existing projection
origins, and admits redacted audits atomically, without retry or fabricated identity.
Plans expose current origins/effect and explicit future-member delegation. Shared
structural eligibility avoids a second grant predicate; existing role flags stay.

Native service/CLI/caller checks include stale/recovery/audit/concurrency cases and
a compiled-CLI -> real SCIM -> existing provider stub/real OIDC SQL binding ->
BoundSession grant -> independent CLI disable/revoke oracle. See
[mapping checkpoint](implementation/identity-group-mapping-checkpoint-2026-10-03.md).
This new phase requires independent parent review. Other roles, profile/doctor,
full-scale performance, live rollout and beta completion remain open.

### 2026-10-03 — Checkpoint domain-manager Group projection callers

Commit: uncommitted implementation checkpoint; no commit created

Affected: internal/roleprojection; internal/scimstore/{sql,role_projection}.go;
internal/authn/{sql_store,projection_test}.go; internal/api/{scim,api_test,
group_projection_test,group_projection_race_test}.go;
internal/rolebinding/{rolebinding,origins_test}.go; cmd/gotth-mail/main.go;
Group-role feature README and identity Group-projection checkpoint evidence.

Parent admitted the unchanged storage/operator/issuer/read prerequisites after two
fresh independent reviews, explicitly accepting the disclosed common-request
coherent-snapshot cost (+32–40%, about 0.34–0.43 ms). This is not new performance,
production-SLO or whole-feature admission.

Add a caller-owned SERIALIZABLE domain-manager projection leaf, exact canonical
SCIM ownership/membership predicates, independently audited origins, structural
retraction under missing/changed issuer and preserved operator ownership/UUIDs.
Wire canonical SCIM Group/User/delete and verified OIDC admission transactions;
failed projection keeps consumed OIDC attempts spent. Correct the demonstrated
operator-preview/read disagreement for mapping/binding role-domain mismatch.
No mapping CLI/service, other-role projection, deployment or signing/UI integration.

Real native SQL and caller RED/GREEN cover origin diffs, no-op tuple DML, audit
and source-DML rollback, session revocation, first-login convergence and the
absent-identity login/SCIM-removal race. See
[checkpoint evidence](implementation/identity-group-projection-checkpoint-2026-10-03.md)
for exact lanes, source receipts and outstanding gates. New writer changes still
require independent parent review; this is partial implementation, not beta admission.

### 2026-10-03 06:25 CDT — Prepare durable Group-role origin storage

Commit: uncommitted implementation checkpoint; no commit created

Affected: migrations/0019_group_role_projection.sql; internal/store/store.go;
internal/store/{group_role_migration_test,migration_parity_test}.go; workflow.toml;
internal/rolebinding/{rolebinding,origins_test}.go; internal/identityruntime;
internal/authn/{sql_store,group_roles_test}.go; internal/api/{api,scim}.go;
cmd/gotth-mail/{main,identity_runtime,identity_runtime_test}.go;
cmd/gotth-mailctl/main.go; Group-role feature README; this changelog.

Add operator-owned default/revision columns, durable mapping tuples and independent
Group source edges while retaining 0018 binding uniqueness and prior migration
checksums. Activate the identity child without closing historical prerequisites;
the incomplete UI feature is blocked for owner reprioritization.

Verification: missing-migration RED and focused real PostgreSQL16.14/17.10 GREEN
cover legacy backfill/default INSERT, mapping shape/uniqueness and source FK
semantics; the full store package passes on PostgreSQL16.14, focused PostgreSQL17
race and store vet pass. Operator grant/revoke now changes only its origin and
preserves other Group sources/UUIDs, with coherent previews and versioned digests.
Focused native operator RED/GREEN proves ownership, stale-source rejection and
audit rollback; operator package passes normal PostgreSQL16 and race PostgreSQL17.
The shared protected issuer loader and unchanged scope hash are wired into service
and operator CLI. Session role reads now use a coherent snapshot and narrow
current-issuer/enabled Group-source guards, preserving operator roles and the
mailbox-only API actor. Native guard RED/GREEN, protected-loader race tests, OIDC
normalization and real operator CLI tests pass. The authn package passes on
PostgreSQL16; final focused PostgreSQL17 race checks cover loader/service/CLI/read
guards. Existing SCIM/API/UI regressions, scoped vet and both command builds pass.
Full-repository, independent-review and projection lifecycle gates remain open.
This is prerequisite preparation, not a Group grant path, completed projection
or beta admission.
No live migration, fence, deployment or signing-runtime integration occurred.

### 2026-10-03 05:53 CDT — Specify exact Group-to-role projection

Commit: uncommitted contract checkpoint; no commit created

Affected files: docs/prd/PRD-v2-identity-provisioning.md; docs/architecture/v2-identity-provisioning.md; docs/implementation/v2-identity-provisioning.md; docs/implementation/release-1.0.md; workflow.toml; workflow/features/release.1-0/role-binding-operator/{prd,architecture,implementation-spec}.md; workflow/features/v2.identity-provisioning/group-role-projection/README.md; this changelog.

Specify IDP-GROUP-001..007 and a planned domain_manager-first implementation: exact verified mailbox/User/scope/issuer binding, independent grant origins, atomic SCIM/OIDC projection and current-issuer read guards. Preserve operator flags and mailbox-only API actors. Define protected shared issuer configuration and old-writer fencing; distinguish feature-disable from schema/binary rollback. All-role, profile/doctor and live proof remain open. No production code, migration number or live authority is added.

Verification: docs-only standard TOML, dependency/path/link and diff checks are recorded in the contract evidence. No Go/native tests, implemented capability or installed workflow-checker PASS claimed.

### 2026-10-02 — HTML inventory cursor/navigation slice (uncommitted)

Wire only the authenticated HTML inventory to ListInventoryPage; parse bounded
canonical after cursors after existing admission. Add native First/Next inside
the fragment region and preserve theme/current-page refresh. Selected errors and
legacy List/API/detail/authority/JS behavior remain unchanged. Regenerate inventory
Go/CSS with pinned tools (two identical writes plus check); no manual output edits.
PG170010 focused38PASS, HTTP276PASS/2existingSKIP, focused race38PASS, vet0,
existing extension API19PASS. Parent review pending; no native browser/PG16/fullroot
or performance admission. Target encoding/stored-key compatibility remains open;
no arbitrary-schema traversal or whole-feature completion is claimed.


### 2026-10-02 — Inventory page service implementation (uncommitted)

Add ListInventoryPage:50 selected entries, keys-only lookahead, complete selected
payload/status decoding and fail-closed membership checks. Preserve legacy List
and all existing API/UI callers. No quotas, migration or HTTP integration.
Qualified PG17 checks:49 focused and49 race records;282 affected-package records;
vet passes. New method statement coverage100%; live concurrency, PG16, navigation
and performance gates remain open. Unicode-domain tests explicitly bind a UTF8
fixture without changing shared fixture policy. Earlier failed staging/fixture
attempts are retained. Independent implementation review remains pending.

### 2026-10-02 — Inventory page service tests WIP; source admission blocked

Add focused inventory_page_test.go only; no production pager implementation.
Native RED was not reached: staged overlay modes0600 disagreed with expected0644
under retained077. All535source bytes/sizes matched. Preserve source-gate failure;
no Go tests run, no behavioral/compile RED or GREEN claim, no equipment repair or
retry. Parent review/continuation authorization required; feature staysin_progress.


### 2026-10-02 — HTML inventory pagination contracts only (uncommitted)

Record owner40028 approval for paginated HTML inventory with every stable-dataset
entry reachable and malformed OFF-PAGE records isolated, without new quotas.
Specify fixed50/keyset/keys-only lookahead, complete selected-row error behavior,
ordinary navigation and preserved API/List/detail/authority boundaries. PRD,
architecture, implementation spec and ordered feature plan updated; implementation
remains held for parent review. No Go/SQL/template/asset/test changes or tests run.
Existing accepted534-source verification is retained, not pagination evidence.


### 2026-10-02 — Recovery artifact pin wrapping (uncommitted)

Add four semantic break opportunities to the current valid artifact pin in the
metadata-recovery document. Preserve exact pin text, ordinary escaping for direct
invalid inputs, previous-artifact output, forms and confirmation authority.
This targets the measured CSS-blocked artifact text overflow only; verification
is task-scoped, not full CSS-absent accessibility or feature admission.

### 2026-10-02 05:10 UTC — Explicit public actor-mapping fixture (uncommitted)

In `cmd/gotth-mail/notification_env_test.go`, chmod the initial synthetic
actor-mapping file to 0644 and assert its observed mode before the unchanged
private-file rejection check. The subsequent 0600, duplicate-actor and malformed
mapping branches are unchanged, as are production policy and runner umask 077.
The previous full-run failure remains preserved. One full nonrace diagnostic
without failfast is pending to collect independent failures; no assertion changes.

### 2026-10-02 05:01 UTC — Explicit public-file negative fixture (uncommitted)

In `cmd/gotth-mail/front_auth_env_test.go`, explicitly chmod the synthetic
front-auth token fixture to 0644 and assert its observed mode before calling
production. This preserves the rejection oracle under a restrictive inherited
umask; the private temporary directory and production authorization are unchanged.
The prior full nonrace run exposed the fixture's masked-creation assumption.
Fresh full nonrace verification is pending; the failed receipt remains retained.

### 2026-10-02 — Current-grant secret-status SQL selection (uncommitted)

Filter secret-status reads by instance and current granted slots, preserving
valid projections and empty-query errors. Retired secrets remain retained for
rollback, uninstall checks and confirmed all-secret deletion. Retired SQL
infinity timestamps are no longer scanned; current-slot infinity still errors.
Internal NUL-bearing array arguments may fail; no persisted-jsonb NUL path is
claimed. Row-transfer evidence is not a latency or whole-request bound.

### 2026-10-01 — Recovery native focus styling follow-up (uncommitted)

Apply existing detail form/control/focus styles to the dedicated recovery root.
The earlier metadata-recovery entry records its original no-CSS-change scope;
this follow-up changes only recovery presentation and regenerated detail assets.
Evidence: .artifacts/gotth-mail-recovery-ui-focus-repair-20261001.md.

### 2026-10-01 — Recovery-only UI for invalid stored metadata (uncommitted)

Classify decoded metadata before field projection. Dedicated scalar-only recovery
detail preserves existing authorized recovery and outstanding update confirmations,
while withholding test/enable/configuration/new update previews. Intentional status
change: decodable unknown field kind uses recovery200 rather than blanket500.
Service/API/decoder/schema/auth/CSRF and CSS are unchanged. Add route regressions;
verification and remaining gates are recorded in the scoped implementation handoff.


### 2026-09-30 07:04 CDT — Checkpoint target-bound administrator operations and uninstall receipt

Commit: current commit; hash assigned by Git after commit

Affected files: internal/extensionsadmin/service.go and associated target, boundary,
concurrency, uninstall, service and restart tests; internal/api/extensions.go and
boundary/target tests; internal/httpui/extensions.go, detail templ/generated Go/CSS,
detail/target/boundary tests and existing audit/configuration/inventory tests;
internal/testpg/testpg.go and lane tests; scripts/generate-extension-inventory.sh;
this changelog and the 2026-09-30 administrator checkpoint evidence.

Require all four Apply paths to bind the authorized route target to their locked
preview before mutation. Preserve PostgreSQL UUID identity/aliases and existing
authorization and confirmation behavior; reject intrinsically oversized UUID text
before a database cast. Add real authority, no-delta, recovery and concurrency
regressions and explicit PostgreSQL test-lane validation.

After successful uninstall, return a buffered, escaped templ receipt rather than
claiming that the entire registry is empty. Add isolated generated detail CSS and
extend the pinned generator to two explicit component pairs. Other detail views,
service behavior and existing inventory assets remain unchanged.

Verification reused from sealed candidates, not rerun for this documentation-only
closeout: selected target suites: 189 named passes on each native PostgreSQL 16.14 and
17.10 lane; current D1 HTTP UI: 119 named passes/two disclosed opt-in skips; separate
actual generator: 26 passes/zero skips; two fresh generations matched. Target-repair
and D1 source each received two independent scoped clean reviews. See checkpoint
evidence for identities, applicability and limitations.

This is an owner-requested development checkpoint, NOT feature or beta admission.
D2–D4, native visual/browser floors, coverage/resource/bounds and performance gates
remain open. No release, tag, deployment or workflow-state transition.

### 2026-09-27 09:07 CDT — Admit the bounded inventory renderer development checkpoint

Commit: current commit; hash assigned by Git after commit

Affected: the inventory renderer/shared assets/build and test files listed in the
three implementation entries below; canonical inventory admission/evidence and
feature README clarification. Two independent fresh whole-patch reviews returned
CLEAN on frozen3828ddcc. Parent verified source/evidence identities and unchanged
executable bytes through this narrative closeout.155 affected tests, final native
67.93s, build/generator/builder checks and two clean final-product generations pass.
See canonical2026-09-27-renderer-inventory-admission.md for full identities and limits.

This supersedes earlier pending-admission statements for this bounded slice only.
No workflow completion, WIP PR merge, tag, image build, deployment or beta admission.
List/detail bounds and the remaining native/identity/release gates stay open; cost
evidence is synthetic-DOM/browser only.

### 2026-09-27 08:43 CDT — Repair renderer review edges and extend native evidence

Commit: current commit; hash assigned by Git after commit

Affected: inventory companion/tests, generator and overlap tests; existing Go browser
fixture/driver; canonical renderer evidence and this changelog. No service/schema/auth,
List/detail/POST behavior, vendor, workflow state or production routing change.

Watchdog now retires then aborts safely, rejecting owned late/unmatched responses
before response-header commands or swap. Generator refuses source/cache/temp overlap
in either direction before staging. Focused honest red/green evidence retained.

Native equipment adds isolated normal-origin storage BLOCK with explicitly
server-injected existing synthetic authentication pair and real401 before/after;
original browser-cookie matrix unchanged. Native Back/Forward positively observes
persisted row clearing and fresh authentication. Separate cache-disabled/enabled
loader/DOM cost samples disclose synthetic response row expansion, polling bounds,
cumulative process-RSS limits and lack of multirow SQL/speedup claims. Original reds
and equipment corrections preserved. Final affected/build/generator/native evidence
and source mapping are in the review1 HANDOFF; independent admission remains pending.

No commit, push, images, deployment, cross-engine/live-identity or beta admission.

### 2026-09-27 07:35 CDT — Guard inventory vendor loading and require generation checks before image builds

Commit: current commit; hash assigned by Git after commit

Affected files: inventory.js, inventory templ/generated source/tests; inventory browser
driver and fixture count; production-image builder and its contract test; this
changelog, v3 implementation spec and canonical inventory evidence.

Sole companion loader accepts four exact actual-browser full URLs only, waits for
complete/window-load and fixed shell/meta/CSS prerequisites, appends one immutable
vendor script, then rechecks version/config/URL before activation and requests.
Rejected URLs retain authorized ordinary HTML and pageshow protection. Reviewed
public current-path bookkeeping and fixed transient probe/collision are explicit;
unknown query persistence is repaired, not waived. Vendor/webmail bytes unchanged.
Mandatory generator --check follows build identity guards and precedes Docker
without source writes, downloads or optional skips.

Verification: synthetic-canary actual-browser red4.42s, repaired native PASS24.28s;
22 rejected URL/path cases with unchanged sentinel maps/native storage events,
four canonical real refreshes, delayed vendor, after-DOMContentLoaded/before-complete
observation, injected opaque-origin storage denial, seven visual/no-script cases,
seven fallbacks and ten terminal errors. SQL/auth/runtime/cleanup pass. Seven PNGs
inspected. Affected packages, actual pinned generator checks/denials/stale output/
reproducibility pass. Builder sequencing red then green uses stubs, not image proof.

Limits: raw failures/equipment corrections preserved; no speedup, fixed List bound,
full images, cross-engine/floor/live identity or feature/beta admission. No commit,
deployment, service/schema/workflow change, vendor patch or storage API override.

### 2026-09-27 06:12 CDT — Implement inventory GET renderer; withhold persistence admission

Commit: current commit; hash assigned by Git after commit

Affected files: go.mod/go.sum; internal/presentation tokens/assets/tests and moved
HTMX asset/license; internal/api webmail CSS/asset wiring and regression tests;
internal/httpui inventory Go/templ/generated source/tests/assets and GET wiring;
tools/renderer module/standalone manifest/license; inventory generator/browser
scripts and minimal existing browser runner/fixture selection; this changelog,
v3 implementation spec and extension-management-ui inventory evidence.

Implements only escaped inventory GET with all projected fields, shared scalar
colors, exact webmail byte preservation, fixed public assets and an outer buffer.
Theme links work without scripts. HTMX opt-in requires safeguards/config/both CSS
assets; exact valid response plus completed swap is success. Terminal failures
settle busy state, and authorization loss clears old rows. Detail/POST/audit,
service/schema/workflow behavior is untouched. The pinned standalone generator
runs offline/private, validates explicit tools and rejects stale checked-in output;
no npm or compiler at production startup.

Verification:141 named/subtests across directly affected presentation/httpui/api
packages pass with PG16.14 where required. Exact legacy CSS11102-byte/hash6645ad2c
and HTMX71ea6718 served-byte/header checks pass. Generator denials, stale-output
checks and reproducibility pass. Companion and actual-driver closeout fault checks
pass. Native evidence exposed a deferred-init bug; focused red/green repair waits
for DOMContentLoaded during interactive readiness. Chromium151 then exercised seven
visual/no-script theme cases, forced-color focus, real row replacement preserving
focus/scroll, seven fallbacks, ten injected failures and native reload recovery.
Seven screenshots inspected; SQL unchanged; no bearer/non-GET/receiver/runtime
activity; cleanup passed. Render-only latency/allocation/RSS samples retained,
without a speedup, full-request or fixed-bound claim.

Overall native gate stays FAIL: pinned HTMX writes the current public path to
sessionStorage before configuration, rejected by the strict zero-session-storage
probe. No localStorage or credential value observed. Parent must resolve the
contract/oracle boundary; no library fork, global storage shim or relaxed assertion.
Initial syntax, version-check, temp-path, CSP-injection and truncated-read equipment
failures are retained with fixes. Cross-engine/floor, live identity, unlimited List
resource bounds, detail migration and B1/beta gates remain open. No admission,
workflow transition, commit or deployment.

### 2026-09-27 02:23 CDT — Exercise native rollback and separate restored-A readiness

Commit: `70defe10d973d3fa00741c3ef2ed43b622d0aeb4`

Affected files: cmd/gotth-mail/extensions_acceptance_test.go, cmd/gotth-mail/extensions_browser_test.go, scripts/extensions-browser-smoke.mjs, scripts/extensions-browser-smoke.test.mjs, scripts/extensions-browser-acceptance.sh.

Adds isolated rollback mode: handler setup independently captures A before confirmed B update, changes B endpoint/timeout and rotates secret. Native blank denial, wrong-phrase denial, correct displayed-phrase rollback and reload use exactly two POSTs. SQL requires complete A restoration, full B previous snapshot, retained rotated encrypted secret and exact audit. After browser/HTTP shutdown, separate real A Service.Test must pass before combined success. Existing observer/server/B staging reused; runner sixth B argument limited to update/rollback.

Verification: first actual rollback run PASS10.56s on development Go1.26.6 race binary, PostgreSQL16.14/160014, Chromium151.0.7922.71. Exactly two native POSTs (wrong denial, success), blank required denial, complete independent A/B snapshot and rotated-secret AES-GCM/SQL/audit/reload checks. After browser exit0/HTTP shutdown, real restored A PID229/open-inode616d9fd3…/private socket Start/Probe/Stop proves readiness revision5; combined gate passes, route absent/receiver0. Namespace zero live fixture processes/residual paths. Scoped compile/vet, 76 named oracle subcases plus combined-result and sequence guards, 30 controlled driver shutdown cases plus native Enter, 14 retained runner argument cases pass. Initial synthetic valid-delta red used non-JSON placeholder table strings; corrected fixture data only before any physical run, retained initial source/log/exit. No product edits, old physical/full-suite reruns or admission claim.

Limits: injected setup/login, no delivery/Enable, no old physical gates; renderer/shared tokens and B1/beta remain binding.

### 2026-09-27 01:50 CDT — Exercise native pinned update and separate B readiness

Commit: `b57d641cf293d9534641fb3cc503de68f41d2ac6`

Affected files: cmd/gotth-mail/extensions_acceptance_test.go, cmd/gotth-mail/extensions_browser_test.go, scripts/extensions-browser-smoke.mjs, scripts/extensions-browser-smoke.test.mjs, scripts/extensions-browser-acceptance.sh.

Adds isolated native Update Preview/blank-confirmation denial/Apply/reload, independent SQL/crypto/snapshot/secret/audit checks and no runtime calls. After browser shutdown and frozen native proof, one separately labeled Service.Test proves pinned B Start/Probe/Stop. Combined success requires both. Extracts only existing B staging, preserving its closed trust and old call order; sixth runner argument is B only for update.

Verification: development Go1.26.6 race compile and scoped command vet pass; 10 update-preview crypto/SQL cases, 51 directly affected shared oracle subcases, 25 controlled driver shutdown cases plus native Enter helper, and 10 runner argument guards pass. Native run2 PASS10.59s: two POSTs, blank denial, independent update SQL/AES-GCM/audit/previous-A snapshot and reload; browser exit0 before separate B Test observes actual binary6248244f… PID231/socket Start/Probe/Stop, revision3 readiness audit, no route/receiver. Namespace zero live fixture processes/residual paths. Run1 was equipment red: RFC3339 expected a zone on SQL timestamp-without-time-zone JSON; corrected parser preserves exact ten-minute expiry checks, failure source/log retained. B staging block verified byte-identical at its original old-path position. No old physical/full-suite reruns, production changes or canonical admission.

Limits: unpublished version-only alpha.2; injected setup/login; no Enable/send/rollback/schema migration; renderer/shared tokens and B1/beta remain binding.

### 2026-09-27 01:30 CDT — Verify native Enable and Disable as one safe cycle

Commit: `ecf3cd53c50797ce4aa838945bf3a4d958b16fdb`

Affected files: cmd/gotth-mail/extensions_browser_test.go, cmd/gotth-mail/extensions_acceptance_test.go, scripts/extensions-browser-smoke.mjs, scripts/extensions-browser-smoke.test.mjs, scripts/extensions-browser-acceptance.sh.
