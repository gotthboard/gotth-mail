# Recovery Phase A — implementation checkpoint, 2026-10-04

Implemented and accepted by parent after two fresh independent PASS reviews
at00:43UTC. NOT Phase B/C, live
fence, compatible-pair, rollback/restore or full feature/beta admission. No commit.
Before code: prior55 doctor hashes verified plus parent's admission/renderer image;
all successive history remains preserved. PRD→architecture→spec→plan were published.

## Mechanism

Only identity group-feature-disable preview --config FILE / apply --config FILE
--confirm DIGEST is new. Closed flags, JSON local output, errors exit1 with no raw
config/SQL payload; no issuer file, selectors, force/re-enable/fence flags or API.
Existing operator commands retain guards and behavior. Preview is genuinely read-
only/repeatable. Apply is one SERIALIZABLE transaction,15s context/no retry/chunks.
SET LOCAL search_path=pg_catalog,public,pg_temp and row_security=off precede reads.
All four qualified NOWAIT locks precede EVERY SELECT: ledger SHARE then mapping/
binding/source SHARE ROW EXCLUSIVE. New SQL/functions qualified; reused leaves
resolve trusted public before temp. RLS errors, not bypasses. Trusted session/public
ownership/CREATE exclusions and external quiescence are preconditions, not scan output.

ValidateCurrentSQL only reads existing ledger and requires every registered clean
checksum-matching migration/no unknowns. It does not migrate/bootstrap or certify
arbitrary physical-schema integrity. Existing MigrateSQL/startup policy unchanged.
Full ordered metadata/ledger/database/user snapshot binds the versioned SHA256 plan;
NULL distinct. Local plans disclose exact UUID/role/target/revision/effect, not issuer/
scope/Group/subject/payload/credentials. Digest is not a fence or unique clone identity.

Reject malformed mapping/role/target/revision, dangling FK, crossed/duplicate sources
and preexisting nonoperator orphans before DML. Missing Group, old issuer, disabled
local flags and malformed User payload do not block withdrawal. Enabled OR source-
bearing mappings change once to disabled/revision+1, preserving rows/tombstones.
Same-tx RemoveMappingSources revises/audits each origin and removes only newly
orphaned nonoperators. Operator bits/UUIDs/identity/role/targets and history remain;
per-mapping plus one summary audit. Exact postcondition validates mapping metadata,
operator tuples/revisions and ledger, with zero enabled mappings/sources/orphans.
No-op changes no data/revision/timestamp/audit. Errors rollback; ambiguous commit
requires inspection, never automatic replay. No projector rewrite or grant/repair.

## Native verification

Development's existing Go1.26.6/PG16.14+17.10, offline env-i, GOMAXPROCS2/-p1,
known short-socket launchers,15m package limits and inherited128MiB file/core1.
No old binaries, credential fencing/session termination, service-pair swaps,
pg_dump/restore, host configuration, provider or live operations were performed.

FULL PG16 affected rolebinding633.782s, store382.581s, CLI61.962s: native exits0.
Final PG17 race selected rolebinding77.369s, store8.249s, CLI14.426s,
projector18.681s, actual API CLI/SCIM/OIDC-consumer45.872s, BoundSession8.738s:0.
Two test-only strengthenings after full snapshot (postcondition/overflow/cancel and
missing-ledger-query error) passed final race; production bytes unchanged. This is
explicit reuse, not a claim the full suite was rerun. Vet/current binary build
passed (five-package vet, service build, CLI build:0/0/0); exact source bridges
are in the final ignored packet.

Actual nonsuperuser/nonowner profiles: SELECT-only preview; apply source DELETE
without UPDATE; mapping/binding UPDATE, orphan DELETE, audit INSERT. PG16 ledger
UPDATE is real DML capability (unused, equality and statement traps); PG17 MAINTAIN
without ledger UPDATE, negative UPDATE probe. Neither ownership nor BYPASSRLS used
for ACL proof. Denied schema/table creation, history DELETE and SET ROLE; no role
memberships/public-table ownership. Existing complete-schema MigrateSQL function
runs under the exact stronger ledger grants, SELECT-only counterexample fails.
This is not full service startup/restart qualification. MAINTAIN's VACUUM/ANALYZE/
CLUSTER/REINDEX/REFRESH MATERIALIZED VIEW/LOCK powers are explicitly not zero-power.

Separate hostile setup exercises public function, temporary tables, supplied path,
and hiding RLS. Real server statement-order evidence uses installed libpq synchronous
notice handler:59 bounded in-memory LOG notices, exact ordered4locks before first
SELECT; no custom driver, server logfile or raw SQL statement dump. This
trace lane changes only its owned connection client_min_messages/log_statement;
no server configuration file is edited. It is admin setup, NOT the separate
least-privilege proof.

Real SQL tests cover all3 roles/multiple issuers/scopes, operator+two origins,
nonoperator removal, retired/disabled residuals, missing Groups/malformed User,
nonempty history, empty/no-op DML traps, stale mapping/absent mapping/provenance/
binding/ledger/user context, one changing winner, NOWAIT, early cancellation,
corruption, mid/late/deferred audit failure, skipped writes, revision overflow and
postcondition tampering. Database-name digest sensitivity also has a pure model
check; not a cloned-database exercise. Compiled current CLI proves positive/negative
JSON/flags/native exits, missing issuer-file independence, no bootstrap, no-op,
redaction and legacy command regressions. No fake fence flag or live-provider proof.

Coverage: Preview/begin/ValidateCurrentSQL/parser100%; Apply95.7%, readRecovery87.5%,
row drain90%, plan92.3%, postcondition88.9%. Whole-package totals are not feature
coverage. CLI wrapper0% in parent profile because real compiled subprocesses are
not instrumented; their native behavior is observed separately, not counted as
parent coverage. Rare scan/close/RowsAffected/encoding/entropy/transport commit
ambiguity and some defensive model branches remain unproved; no custom driver.

## Cost, history, and remaining gates

Single operation observations: M4/B3/E4 ~48ms PG16/~87ms PG17; M36/B1/E32
~190ms/~307ms. Different conditions/race instrumentation, not matched benchmark,
throughput/SLO/speedup or full-scale proof. Snapshot/JSON materialization O(N) space;
reused per-mapping leaf can reread identities, O(M*(B+E)+Q) with SQL/locks/audit Q.
Only cold administrative path changed; no common-request optimization/revalidation
claim. External/proportional broader performance gates remain open.

Native compile RED preceded service; corruption RED exposed duplicate-source preview
acceptance, fixed with explicit duplicate checks. Incorrect local driver-version
read and generated fixture quote error were corrected without claiming native PASS.
All failures/source variants retained. Forecast384MiB additional is planning, not
hard aggregate/peak enforcement; all-hop growth and old evidence/40MB inactive
fixture remain charged. Final resource/owned-process/socket classification in packet;
no old residue cleanup or graceful-shutdown fiction. Renderer proof untouched.

Phase A parent admission is complete. B requires explicit separate
assignment for persistent old-principal/entrypoint exclusion, actual pair restart,
conditional compatible archive and isolated dump/restore proof. C requires external
host/ingress/credential/supervisor/no-write evidence and explicit live authority.

## Parent admission

Both independent implementation reviews passed without mandatory findings. Parent
read and reconciled both reports and verified the66-file seal. Admission covers
Phase A only. The old document image is preserved; this closeout and completion
of a truncated disclosure sentence are documentation-only. Other65 reviewed files
are unchanged. No native test was rerun or executable changed for admission.

Phase B binary/fence/restart/restore qualification and Phase C external deployment
remain separate; no such proof or live authority follows from this acceptance.
