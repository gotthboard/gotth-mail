# IDP-GROUP-007 all-role checkpoint — 2026-10-03

Uncommitted bounded implementation, accepted by parent after two independent
PASS reviews at21:00UTC. No full-feature or beta completion. The prior domain_manager mapping phase was admitted by the parent
after two PASS reviews; its 45-file seal, 43 unchanged files and two documentation
admission images were verified/preserved before this phase changed source.

## Authorized behavior change

The existing schema already admits global_admin with NULL domain and
(domain_manager, scoped_domain_access) with an exact domain UUID. No migration or
authorization action change is introduced. GroupService and the closed group-role
CLI now support those same three shapes. Global CLI MUST omit --domain, including
an explicit empty flag; scoped roles require a single exact known enabled domain
for admit, resolved by existing domain rules to its UUID. No --scope, selector,
claim/name mapping, Verified=true shortcut or configuration framework is added.
Role whitespace normalization remains compatible with the existing service.

Shared eligibility carries the actual role already selected by SQL. Projector
and pure preview use role plus nullable-domain keys; source invariants require
both equalities. Global insert binds SQL NULL, never an empty UUID. No-target
status exempts only target lookup: current issuer, authentik provider, exact
mailbox-owned canonical User/subject/scope/member, active parsing and common
mailbox/mailbox-domain/source-enabled guards remain. Structural origins survive
local toggles/issuer loss; guarded reads suppress permissions as before. Existing
operator-origin semantics and mailbox-only API actor construction are unchanged.

Changed admit predicts the entire SyncGroup diff across all affected roles and
targets, not only the requested mapping. Two Groups plus operator ownership remain
independent per role/target. Source audit role is passed from the already validated
binding, without a new per-edge query. Binding UUID is retained until the last
origin is gone; orphan cleanup remains delayed until the full identity diff ends.
Disable is mapping-specific and works under issuer loss/deleted Group/disabled
target/malformed canonical User, while malformed protected authority files reject.
No-op writes zero rows/audits and never opportunistically reconciles membership.

The private digest now includes actual eligible roles and uses group-role-plan/v2;
v1 confirmations reject. Pure read-only REPEATABLE READ preview and caller-owned
SERIALIZABLE mutation boundaries, revision/audit atomicity, retirement barriers,
absent-tuple race failure and no hidden retries remain. Public plans disclose
actual role, target absence and future-member delegation; no raw User/provider
payload, subject or credential is added to output.

## Verification and evidence

The ignored identity-all-roles directory under
.artifacts/gotth-mail-beta-resume-20261003 retains the pre-phase archive, every RED,
source snapshot, exact tool/argv/env/version/limit receipt, nested compiled-CLI
hash/native exits, logs, coverage, source bridges and final handoff.

Initial native service/parser RED rejected valid global/scoped input. A stronger
effect assertion exposed a genuine hardcoded planned-binding role; its RED was
retained and fixed. A parser compatibility RED caught role-whitespace drift and
was fixed with the same existing normalization. Historical unsupported-global
rejection now injects a genuinely unknown role; global-with-domain remains an
explicit invalid shape. Existing mismatch/orphan/security tests are not removed.

New native cases cover one Group/all3 roles, two scoped targets, two Groups plus
operator independently per role, NULL global target, partial/final removals and
UUID retention, whole-role source-swap prediction, canonical active/ownership/
provider/current-issuer/local-enabled guards, source audit role, trigger-enforced
zero-DML no-ops, cross-role stale provenance, late audit rollback and concurrent
one-winner admit/disable. Existing exact foreign-scope/duplicate-subject barriers,
SCIM/OIDC rollback and spent-attempt tests remain consumer regressions.

The reused compiled CLI fixture runs all three roles through actual command
preview/apply, real SCIM membership, existing provider stub plus real OIDC callback
and SQL identity admission, BoundSession, existing authz allow/deny, mailbox-only
API actor, and independent Group/operator revoke. A standalone CLI child is not
falsely counted as parent-process coverage. Provider exchange is stubbed: no live
Authentik/browser proof or live global grant occurred.

Final native run inventory and clean full-package outcomes are recorded in the
handoff. The first combined PG16 full runner hit its8m rolebinding timeout; that
FAIL is retained, not promoted. Standard reruns use an explicit15m package limit,
unchanged product assertions and the final candidate. Full API optional container/
browser tests can skip; the run index names every skip rather than claiming a live
browser/container gate. Native PostgreSQL16.14/17.10 and Go1.26.6 only, offline
existing caches and short socket launchers on development; no gateway-heavy tests.

## Cost and exclusions

No accepted BoundSession performance work was reopened; its source is unchanged.
Role-aware keys add bounded string bytes per mapping/binding; SQL already read
role. No new per-edge query remains. E now includes all admitted role/target
origins, so existing O(B+E log E+Q) time/O(B+E+S) auxiliary accounting still applies
with delegated database/lock/audit costs explicit. Small native per-role operation
samples and exact3-binding/6-edge and5-binding/5-edge populations are diagnostic,
not matched throughput, SLO or broad scale proof. No speedup/Amdahl claim.

The main explicit cross-package profile reports84.2% across rolebinding/projector;
new shape helper100%, pure plan96.4%. The late final-family profile is separate.
Rare entropy/driver Scan/Close/commit failure branches remain; no100% repository
claim. Broader scale/restart/fault matrices,
profile/doctor/import/provider configuration, live exact-provider/browser proof,
quiescence/compatible rollback and beta release gates remain open.

## Parent admission

Both independent reviews passed with no mandatory findings. The second review
resumed its preserved checkpoint after a timeout and completed its independent
evidence checks; the timeout itself is not counted as a pass. Parent read and
reconciled both final reports.

Only this admission document changes; its prior image and the47-file reviewed
seal/native proof remain preserved. The other46 reviewed files are unchanged.
No native tests were rerun for closeout. This admits the bounded all-role unit,
not local doctor/profile integration, external provider proof, broad performance,
rollout/rollback or beta release.
