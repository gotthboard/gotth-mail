# Domain-manager projection checkpoint — 2026-10-03

Uncommitted partial implementation on the existing c365445-based Group-role tree.
No live migration, deployment, publication or beta admission. UI/signing work stays
separate; workflow status remains in progress.

## Admission boundary

Parent admitted the unchanged 26-file storage/operator/configured-issuer/read
prerequisites after two fresh independent PASS reviews. Historical receipts and
matched cost remain under
.artifacts/gotth-mail-beta-resume-20261003/identity-implementation/.
Parent explicitly accepted common-request coherent-snapshot cost of about
0.34–0.43 ms / 32–40% in that bounded fixture. No performance redo, speedup or
production SLO claim follows. This checkpoint adds new writer behavior requiring
new independent review. Mapping admission/service/CLI, other Group roles,
profile/doctor, rollout fences, compatible rollback and beta/live proof remain open.

## Mechanism

- internal/roleprojection accepts caller-owned SERIALIZABLE transactions and
  immutable issuer/audit metadata. No Begin/Commit/retry/operator Apply/network or
  fabrication of verified identities. Mapping roles beyond domain_manager reject.
- Exact identity/mailbox-linked User/provider/subject/scope/issuer and live Group/
  membership equalities are explicit. Canonical bytea JSON uses pinned gotth-scim
  DecodeDocument: omitted active is true; malformed/nonboolean values reject.
- Configured issuer gates additions, not retractions. Prior origins are inspected
  independently of new admissible membership. Valid old origins survive mere
  issuer/local-toggle changes and remain subject to read guards. Stale origins
  retract despite missing/different issuer. Origin swaps preserve the binding UUID.
- Every origin change increments binding revision and writes a redacted success
  audit in the same caller transaction. Cross-table role/domain mismatch rejects.
  The demonstrated operator preview/read mismatch is fixed by binding exact
  role/domain equality into source snapshot, digest and effective_after.
- SCIM receives authority before handlers exist. Group reconciliation follows
  member replacement; User reconciliation follows mailbox persistence. Group
  deletion tombstones mappings/retracts before cascade; User deletion reconciles
  after canonical disappearance. Disable/re-enable cannot revive revoked sessions.
  Callback runs once and memory follows commit. Store-only conformance mode with
  no Identity service exposes no HTTP projection; production constructor rejects
  missing Identity.
- OIDC admission is SERIALIZABLE: verified exact binding, projection, session and
  login success audit commit together. Earlier attempt consumption stays committed
  on any later projection/audit/serialization failure; fresh login is required.

## Native evidence

Ignored evidence root:
.artifacts/gotth-mail-beta-resume-20261003/identity-projection/.
Its final handoff/index records exact sources, argv/environment/tool identities,
native exits and closure. Existing development-host Go1.26.6, PostgreSQL16.14/
17.10, standard testpg and qualified short socket launchers only; GOMAXPROCS=2,
-p=1, offline/env-i/offroot and unchanged file/core ceilings.

Focused native GREEN checkpoints cover the full leaf, full operator package,
real SCIM HTTP lifecycle/audit/once-callback and store conformance, and real
CompleteCallback/SQLStore OIDC admission. The cross-caller race pauses an actual
SQL identity insert, commits an actual SCIM membership removal, then establishes
SQLSTATE40001, one insert attempt, zero leaked authority and a fresh login without
a stale role. Provider verification/exchange is a test stub, not live Authentik or
browser proof. Final package/static/build lane results are indexed in the handoff.

Independent SQL row oracles cover foreign scope/ownership/subject/provider/issuer,
canonical disable, two Groups, operator/default ownership, source swaps,
audit/source-DML rollback, no-op DML and absent-row races. Native transaction tuple
counters for one identity/two sources show one binding insert, two binding revision
updates, two source inserts and two audit inserts. Reconciliation repeated in that
transaction adds zero tuple DML. These are not wire-query/WAL/latency counters.

## Cost and remaining limits

SyncIdentity decodes one bounded User and materializes its binding/origin/mapping
sets. Every changed edge performs source DML, revision and audit work. SyncGroup
visits current members plus prior owners and reconciles each identity. Across-
issuer scope/group mapping queries may scan mappings because existing tuple
indexes lead with issuer. No speculative index or optimization is added. SQL plan,
lock, concurrency and allocation costs are named delegated variables, not hidden
constant-time claims or production-scale performance admission.

Coverage is scoped, not 100% repository coverage. Rare entropy/driver scan/close
failures and unrelated API surfaces remain uncovered; SQL fault and real-caller
checks cover relevant atomicity/security branches. Full-repository, all-role,
long-duration, browser, live-provider and production performance gates remain open.
No old proof, failed fixture history or capacity ledger was reset.

## Scoped phase admission — 2026-10-03 18:01 UTC

Two fresh independent reviews passed with no mandatory defects. Parent read both,
reconciled their evidence and admits this bounded projection/caller phase. This
supersedes the earlier pending-review wording; it does not admit missing mapping
commands, other roles, full-scale performance, live rollout or beta completion.

The37-file reviewed seal and native proof remain historical and unchanged. Only
this documentation record changes for admission; tested executable bytes are
unchanged and prior checks are reused, not rerun. Reports and preserved pre-closeout
document are retained under the identity-projection evidence root above.

Explicit exclusions remain: provider exchange was stubbed, failures require fresh
login, package coverage is not repository coverage, tuple counters are not latency
or wire measurements, and absent owned processes do not certify graceful child
shutdown. Next approved product unit is operator mapping admission/disable.
