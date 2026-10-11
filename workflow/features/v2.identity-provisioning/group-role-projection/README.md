# Exact Group-to-role projection

Final-candidate review closure: two fresh independent cold passes completed sequentially after the documentation correction. Parent inspected both and confirms the scoped Phase B acceptance below. Earlier retained-context confirmations are not counted as fresh passes. No Phase C/live/beta or deployment admission follows.

ID: v2.identity-provisioning.group-role-projection. **In progress**, not done.
Canonical state is workflow.toml. The identity child is no longer the sole active
selector during the outbound provenance recovery unit; this is an explicit pause,
not Group DONE. Historical identity prerequisite states remain unchanged, scoped
Group integration closeout remains pending, and signing/runtime work is not
promoted by this tree.

## Authority and dependencies

[PRD](../../../../docs/prd/PRD-v2-identity-provisioning.md#durable-group-to-role-projection-planned)
-> [architecture](../../../../docs/architecture/v2-identity-provisioning.md#durable-group-to-role-projection-architecture-planned)
-> [spec](../../../../docs/implementation/v2-identity-provisioning.md#durable-group-to-role-projection-planned)
-> this plan -> bounded implementation after parent prerequisite admission and
notification-writer STOP. This tree remains the sole identity production writer.

Reuse opaque Groups, verified OIDC binding/session revocation and the existing
operator service at the accepted c365445 baseline. Manifest dependencies retain
historical states; parent reconciles prerequisite evidence before activation,
without falsely marking old work done. The implemented operator mechanism is a
baseline input, not a new reverse dependency on its v2-root-dependent release
feature (which would create a parent/child scheduling cycle). Migration
0019_group_role_projection belongs to this feature and was admitted as a storage
prerequisite; its existing contents and historical seal are preserved.
No copying accepted UI WIP.

## First implementation unit and trace

Unit 1 is one domain_manager add/remove path from explicit mapping admission,
through real SCIM HTTP + SQL origins, to existing-session authorization. Begin
with exact issuer/ownership/provenance test fixtures; then implement the required
transaction seams. Mapping roles other than domain_manager reject in this slice.
Estimated 4-8 engineering hours plus reviews/full gates/rollout, not promise.
Checkpoint at 60 minutes: working focused predicate/provenance proof or concrete
blocker; do not build a verification framework. Heavy PostgreSQL/full/race checks
run on development against frozen inputs, not the gateway host.

| Requirement | Files/seams (implemented status below) | Required oracle |
| --- | --- | --- |
| 001 exact mapping | internal/rolebinding/group_mapping.go; cmd/gotth-mailctl/main.go; shared scope helper reused by internal/api/scim.go | Explicit preview/confirm, actor-derived scope; unmapped/name/claim/wrong-issuer deny; stale/no-op/audit failure |
| 002 ownership | internal/roleprojection; internal/scimstore/sql.go; internal/authn/sql_store.go | Preexisting identity plus same subject in another mailbox/scope cannot grant; exact owned User allows; pre-login membership creates no identity, verified login converges |
| 003 origins | parent-numbered migration; internal/store/store.go and migration_parity_test.go; internal/rolebinding/rolebinding.go and tests | Two Groups + operator = one row/three origins; each removal preserves others/UUID; legacy DEFAULT TRUE and Group explicit FALSE; operator effective_after truthful |
| 004 lifecycle | internal/api/api_test.go; internal/authn/sql_store_test.go; internal/scimstore/sql.go | Group DELETE/mapping disable remove only owned origins; SCIM disable/re-enable never revives cookie; audit rollback compares all tables; absent-row grant/login-removal races abort or serialize; used_at stays spent |
| 005 issuer/read guards | cmd/gotth-mail/main.go, oidc_env_test.go; shared protected issuer loader; authn.SQLStore; internal/api/identity_api.go tests; internal/httpui/httpui_test.go | Same normalized protected issuer before handlers; missing/mismatch input denies Group authority; restart issuer A->B makes A origins ineffective, preserves operator; both consumers use guarded store; API actor stays mailbox-only |
| 005 local predicates | internal/ops/v3_test.go; authn.SQLStore tests | Bulk/import local mailbox/domain toggles suppress/re-enable only retained Group origins; no extra cookie-revocation claim; no full SCIM graph read per request |
| 006 recovery | rollout notes; migration/CLI integration tests | No old CLI/reader/writer during migration, ledger alone insufficient; compatible cleanup preserves operator/history; tested schema-compatible rollback build; snapshot data-loss boundary explicit |
| 007 completion | same services; required Authentik profile and doctor consumers | Separate follow-up: global_admin and scoped_domain_access, all-role allow/deny, durable mapping/issuer/domain doctor, live exact-provider grant/revoke and recovery |

The protected issuer loader file name is selected during implementation inside
existing identity/config code, not a new configuration framework. The exact input
and normalization contract is already fixed in the spec.

## Implementation checkpoint — 2026-10-03

Storage prerequisite 0019 adds legacy/operator ownership defaults, revisions,
mapping tuples and independent source edges. Focused PostgreSQL 16.14 and 17.10
tests cover actual prior-schema migration, new default INSERT, mapping shape and
uniqueness, source foreign keys and migration file/runtime parity. The full store
package passes on PostgreSQL16; focused PostgreSQL17 race and static checks pass.
Operator mutations preserve independent origins/UUIDs, disclose effective_after
and reject source drift with v2 confirmation digests. Normal PostgreSQL16 and
full PostgreSQL17 race operator package checks pass.

The shared protected issuer loader, exact existing scope hash and service/operator
consumers are implemented. BoundSession uses a coherent two-query snapshot with
current-issuer/local-enabled Group guards; focused native PostgreSQL16/17 tests
pass. Existing SCIM Group non-authority, audit rollback and mailbox-only API/UI
regressions pass. At that prerequisite-only checkpoint no Group writer was enabled.
Parent admitted the unchanged prerequisites after two fresh independent PASS
reviews, accepting the recorded +32–40% / approximately 0.34–0.43 ms common-read
cost. The old 26-file proof and failed history remain preserved separately.

Source-backed prerequisites at c365445 are the opaque Group/member SQL adapter,
verified OIDC identity/session binding and operator role service. Their historical
aggregate/live gates remain open.

## Bounded projection implementation — 2026-10-03

The caller-*sql.Tx leaf now implements SyncIdentity, SyncGroup and
RemoveMappingSources for domain_manager only. Exact verified mailbox/User/scope/
subject/provider/issuer and live membership are mandatory; canonical active
omission means true. New origins require configured issuer equality; existing
structurally valid origins survive mere issuer/local-toggle changes, while stale
origins retract even with missing/different configured issuer. Mapping/binding
role-domain mismatch rejects; operator preview now agrees with the read guard.
Independent origins preserve one UUID and operator ownership, with per-origin
revision/audit and deferred orphan cleanup across a source swap.

SCIM receives immutable issuer before handlers exist and reconciles after member/
mailbox persistence. Group deletion tombstones mappings and retracts before
cascade; User disable removes origins and revokes sessions atomically. Memory
updates remain after commit and callbacks are not replayed. Verified OIDC binding,
projection, session and success audit now share SERIALIZABLE admission; consumed
attempts remain spent when any later stage fails.

Real PostgreSQL/HTTP/callback tests establish these bounded mechanisms, including
first-login convergence, audit/DML rollback, no-op logical tuple writes and an
actual absent-identity login-versus-SCIM-removal serialization failure with no
leaked authority. Provider exchange remains a test stub, not live Authentik proof.
See [checkpoint evidence](../../../../docs/implementation/identity-group-projection-checkpoint-2026-10-03.md).

Parent admitted the bounded projection/caller phase at 18:01 UTC after two fresh
independent PASS reviews. Its historical 37-file seal and parent documentation
closeout remain preserved; accepted executable checks were not rerun for that
admission-only edit.

## Confirmed mapping boundary — 2026-10-03

The next authorized phase now implements rolebinding.GroupService and the real
identity group-role preview|apply command for domain_manager only. Closed flags
are operation, issuer, scim-actor, group-id, role, domain and confirm, plus existing
config selection. There is no scope/domain selector, free SQL or network authority
input. Protected LoadIssuer is the authority; actor ID derives the unchanged scope.

Pure read-only REPEATABLE READ preview binds exact target, authority, canonical
members/User fingerprints, identity ownership/local flags and independent origin
state into a versioned digest. Changed apply reloads under SERIALIZABLE, mutates
mapping plus existing SyncGroup/RemoveMappingSources and all success audits in one
transaction, with no retry. No-op performs zero DML/audits and no opportunistic
reconciliation. Plans explicitly show future-member delegation and remaining
origins/effective state. Changed tuples are separate confirmed operations; admit
never silently edits or disables another tuple. Retired Group IDs remain retired.

Real native service/CLI tests and a compiled-command SCIM/OIDC vertical oracle
pass; provider exchange remains stubbed. See
[mapping evidence](../../../../docs/implementation/identity-group-mapping-checkpoint-2026-10-03.md)
for exact scope, costs and receipts. Parent admitted this bounded mapping phase
after two fresh independent PASS reviews at19:39UTC. No all-role/profile/doctor/live/fence/rollback/beta completion follows.

## Remaining gates

- Broader restart/concurrency/scale and complete identity feature matrices remain
  open; bounded mapping service/CLI admission does not close them.
- Independent security reviews and required full/race/vet/build admission.
- All-three-role/profile/doctor completion; no static Verified=true live proof.
- Approved live tuple/admission, browser/SCIM grant-revoke, replay, recovery and
  beta matrix. Repository contract work grants no deployment authority.

## IDP-GROUP-007 all-role unit — 2026-10-03

Parent admitted the prior domain_manager mapping checkpoint after two PASS
reviews. Those bounded restrictions above are historical, not the all-role
feature contract. This unit adds global_admin and scoped_domain_access through
the existing schema, shared eligibility, role/nullable-domain keys, mapping
preview/apply and closed CLI. Global MUST omit --domain; scoped roles require it.
Plan schema v2 rejects old confirmations; provenance/recovery/no-op semantics
and existing authz/mailbox-only API boundaries remain unchanged.

Plan: real native RED → minimal atomic all-role mechanism → native PG16 affected
packages + selected PG17 race/compiled CLI/SCIM/OIDC/authz → exact source/evidence
handoff → two fresh parent reviews. No profile/doctor/import/provider/live work.
The [all-role checkpoint](../../../../docs/implementation/identity-group-all-roles-checkpoint-2026-10-03.md)
and ignored identity-all-roles evidence describe actual partial verification;
no full-feature or beta completion follows.

## Local profile/doctor unit — 2026-10-03

Parent admitted all-role phase after two fresh PASS reviews. Next bounded unit:
contracts/status/disclosure table → legacy CLI capture + native RED → read-only
local durable inventory and safe caller wiring → PG16/17 + real CLI/public
redaction/daemon regressions → handoff/two parent reviews. No-config CLI behavior
and grant/authz/renderer surfaces stay unchanged. See the
[local diagnostic checkpoint](../../../../docs/implementation/identity-local-doctor-checkpoint-2026-10-03.md).
Local health is not external profile correlation or live proof; broader
feature/beta gates remain open.

## Assigned recovery Phase A only (2026-10-03)
PRD→architecture→spec updated before code. Implement strict read-only current-ledger
validator, GroupRecoveryService, closed CLI and exact nonsuperuser/namespace/RLS/
atomicity tests. Native RED→GREEN then full affected store/rolebinding/CLI, selected
projector consumers/PG17 race, vet and both current builds; no full API campaign.
90min incl15min closure; plan10/checkpoint45; support15min max. New all-hop forecast
384MiB, prior evidence retained; known owner/file/off-root limits unchanged.
Stop for two fresh parent implementation reviews; do NOT start B or C.

## Assigned Phase B owned qualification — 2026-10-04 00:58UTC
Parent admitted A after two fresh PASS reviews; parent checkpoint-only edit preserved.
Before tests: PRD→architecture→spec→this plan published. Production133 inputs frozen.
Deadline02:55UTC, closure starts02:35, runtime checkpoint01:40. Supporting construction
<=15min then concrete blocker/no renewal. Graphify/LSP/context broker N/A: exact known
source and existing fixtures suffice; no indexing/framework.
512MiB all-hop forecast: current pair reused, old pair/legacy ~80MiB; buildcache growth
~100MiB; new sequential cluster+restore~120MiB; snapshots/logs/proof/localcopies~80MiB;
remainder reserved. Measure before next lane; stop/replan if exceeded, preserve history.
Prior~2.30GiB+A264MiB+renderer/inactive40MB remain charged; owner24GiB/file128MiB unchanged.
Offroot only (root96%inodes), target logs16MiB/absolute128MiB inherited/core1. Existing
Go1.26.6/PG16.14+17.10, no install/fetch/containers/new helper campaign.
Success requires all exact B gates in spec and two fresh parent reviews; partial proof
remains partial. HANDOFFSTOP <=6500B in identity-recovery/phase-b. Phase C OPEN.

### Phase B checkpoint: partial / BLOCKED (2026-10-04 01:30UTC)
Real PG16 authenticated legacy fence/core current+rollback starts/CLI/isolated restore
passed. Full protocol scenario remains FAIL at browser session boundary; no PG17.
Prospective512MiB all-hop forecast cannot fit required remaining lanes; stopped before
next run, retained failures/data. Production133 unchanged. See
[partial B checkpoint](../../../../docs/implementation/identity-recovery-phase-b-checkpoint-2026-10-04.md).
Parent fresh reviews/replan required; no B or C admission and no automatic continuation.

### Phase B prospective continuation — 2026-10-04 01:42UTC
Parent authorizes diagnostic-only first, then evidence-proven fixture repair and
full16/17. TOTAL B forecast768MiB, continuation<=256MiB, original02:55harddeadline
including20minclosure. No new admission or production authority. Preserve previous
FAIL/source/seals; uniquely named new clusters only. Missing gates stay OPEN.

Continuation diagnostic proved expired timezone-mismatched seeded session; only two
Bsession seeds corrected to boundGoUTC. PG16 rerun passes all3browser-role subcases,
then FAILs SCIM GET500; source identifies hand-minted v1/noncanonical fixture record.
No production/ACL change or PG17 run. Separate fixture repair needs parent scope;
aggregate continuationhandoff preserves priorseals and currentFAIL. Still BLOCKED.

SCIM fixture now uses pinned public reconciliation/generatedID. Full native PG16
and17 functional scenarios PASS (41.878s/22.539s), but B remains BLOCKED:52child
core limits were unlimited, violating required crash-output cap; file128MiB held.
Preserved PASS logs and collectorFAIL; no repeat within remaining768MiB forecast.
See continuation/scim-repair handoff for parent cap/retest disposition, not admission.

### Final scoped Phase B acceptance — 2026-10-04

Parent accepted the complete capped owned PG16/17 qualification after two fresh
implementation/evidence reviews and their independent confirmation of the exact
changelog-history restoration. Earlier BLOCKED/FAIL entries above remain history,
not the current B disposition. Native/source bridges and all failures are retained;
no executable change or rerun accompanied documentation repair/admission.
See the final acceptance in the Phase B checkpoint. This does not close Phase C,
live provider/credential/host isolation, broader performance or whole beta gates.

## S+U+I detached integration plan — 2026-10-04

Earlier separate-tree restrictions and owned A/B admission above are historical.
This same detached merge stage contains parent-admitted U547+S15 and now composes
only admitted I69. Canonical PRD→architecture→spec imported before this plan/code.
Group-role integration is active; signing/UI remain incomplete/nonactive, beta
planned. No role/issuer/session/token/confirmation policy changes or new callers.

Verify exact inputs/modes/path union and full changelog history; compose BOTH
notification doctor/parity and explicit0644 fixture assertions. Existing SQL
BoundSession and UI fake-session tests leave a concrete combined authority gap:
add at most one focused existing-file HTTPUI test using real SQL session/current
issuer/origins with allow/deny, Group withdrawal on an existing session, operator
preservation and domain non-escalation. Keep existing API mailbox-only regression.
Then sequential development PG16 affected normal, selected PG17 race/compatibility,
scoped vet/service+CLI builds and ONE new exact-candidate permissions native browser
using existing VM/equipment and actual Go/test/SQL-server cap receipts.

Ignored component-integration-identity packet records source/native/evidence seals,
resources, exclusions and two required fresh parent reviews. No manufactured RED
for verbatim accepted imports; test-only seam can pass immediately. Existing
BoundSession common-read +32–40%/~0.34–0.43ms cost retained, no optimization claim.
Historical original-I ownedB proof is not new merged-artifact recovery proof.
Full recovery/scale/live-provider/fullbeta remain OPEN. No commit/push/deploy.

## Scoped601 composition acceptance and handoff — 2026-10-04

Parent admitted the frozen601-file identity composition after two qualifying
fresh independent passes and final source/evidence checks. The interrupted
normal aggregate remains failed124; its14 incomplete observations were replaced
by a separately completed14-case native job, not retrospectively accepted.
Selected73 normal,29 caller and15 race checks, scoped builds and the exact601
permissions browser gate support only this composition. The invalidated review
was not counted. Original U/S/I inputs and failure history remain preserved.

This supersedes the active integration plan above, not broader Group completion.
Group remains incomplete/nonactive for merged-artifact recovery, scale and live
gates. The next sole active unit is bounded outbound queue-provenance equality;
no role/issuer authority, deployment or whole-beta acceptance is granted.
