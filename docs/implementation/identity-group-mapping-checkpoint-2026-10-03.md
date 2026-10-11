# Confirmed Group-mapping boundary — 2026-10-03

Partial, uncommitted domain_manager implementation; accepted by parent after two
fresh independent PASS reviews at19:39UTC. Existing storage/operator/issuer/read and projection/SCIM/OIDC phases
were admitted separately. Their seals, failures and parent closeout are preserved.
No other worktree, signing/UI work, deployment, migration or live authority changes.

## Operator surface and mechanism

Use identity group-role preview|apply with required config, operation admit|disable,
issuer, scim-actor, group-id, role domain_manager and exact domain; apply additionally
requires confirm. Flags are closed, duplicated/unknown flags reject, preview cannot
accept confirm, and no scope/free-SQL/domain selector exists. Legacy role-binding
commands retain their flags and independent operator origin.

The unchanged protected 4096-byte LoadIssuer supplies authority before group CLI
SQL dispatch. Request issuer, provider BaseURL and other config fields cannot
replace it. Shared canonical normalization/operator validation apply. Stable SCIM
actor ID derives scope through the existing versioned helper. Admission requires
that scope's typed live Group, untombstoned opaque identifier, configured issuer
and exact enabled target domain. Another tuple cannot bypass a retained Group
retirement flag. Disable remains possible for old issuer, missing/deleted Group,
disabled domain or malformed canonical User; malformed/unprotected authority files
still reject. An absent mapping is a true no-op, not implicit admission.

Admit adds/re-enables one exact tuple; it never edits/disables another tuple. A
replacement requires separate confirmed disable/admit operations. Multiple explicit
delegations can coexist. Retired mappings/opaque Group IDs cannot be recycled.

Preview uses a read-only REPEATABLE READ transaction, not savepoints/write-rollback
simulation. Its group-role-plan/v1 digest binds normalized request, configured
authority, derived scope, target mapping UUID/revision/state, typed Group version/
absence/retirement, domain UUID/flags, sorted member User versions/document hashes,
exact identity ownership/local flags, and sorted binding/source revisions/state.
Shared roleprojection eligibility supplies the structural predicate for changed
admit; recovery/no-op reads metadata without admission-only canonical parsing.
No raw User document, subject, credential or provider payload enters public plans
or audits. Public Group ID/scope hash, role/domain, origins/counts/effective state
and future_member_delegation identify the reviewed delegation.

Effective state describes the requested role/domain for listed affected identities
(and their listed origin outcomes), not every possible authorization/session in
the system. A valid session is still required. Operator and other sources remain
visible; no unsupported promise of complete access revocation is made.

Apply opens one SERIALIZABLE transaction, rereads/recomputes confirmation, rejects
stale/old-schema/missing/wrong digests, then creates/enables or disables mapping.
Changed admit invokes existing SyncGroup; disable invokes RemoveMappingSources
only for its own mapping. Mapping revision and redacted mapping/source success
audits commit with bindings/origins or roll back together. No hidden retry, identity
fabrication, source promotion or membership-driven session revocation. No-op writes
zero rows/audits and never reconciles opportunistically. Canonical SCIM disable
semantics and current-session guards are unchanged.

## Evidence scope

The ignored identity-mapping evidence root under
.artifacts/gotth-mail-beta-resume-20261003 contains exact source/tool/environment/
argv/native-exit receipts, original RED/fixture failures, row oracles and handoff.
Existing development-host Go1.26.6, PostgreSQL16.14/17.10, testpg, short socket
launchers, env-i/offline caches, GOMAXPROCS=2/-p=1 and file/core ceilings only.

Full affected rolebinding/projector PG16 packages pass. Focused PG16 and PG17 race
checks cover mapping authority/namespace/zero-identity delegation, two Groups plus
operator, true no-op, stale Group/member/User/identity/provenance/mapping/domain/
authority, late mapping/source audit rollback, retired-tuple rejection and absent-
tuple admit/disable races. Practical source mismatch/orphan rejection is checked
separately. The compiled CLI is exercised through closed flags/protected-file
failures and the real SCIM -> existing provider stub/real OIDC SQL binding ->
BoundSession -> independent disable/revoke vertical path. Final handoff indexes
exact lane populations, compile hashes, exits, vet/build and closure.

Provider exchange remains a stub; this is not live Authentik/browser proof. SCIM
failure-request audits intentionally remain outside failed canonical transactions;
rollback oracles distinguish those from success audits. No global 100% coverage
claim: rare entropy, driver scan/close/commit failure branches and broad unrelated
surfaces remain gaps. Cross-package coverage of rolebinding/roleprojection is
explicitly instrumented; separately built CLI child code is not falsely counted
as parent-process coverage.

## Cost and limits

No accepted BoundSession cost rerun/optimization. New mapping previews retain
metadata/hashes rather than raw User payloads. They read members linearly, then
exact affected identity eligibility and binding/source provenance; source reads
currently cost one query per existing binding. Full changed-admit prediction and
SyncGroup may reconcile other origins of those same affected identities; the plan
models/discloses them rather than simulating only its own edge.

Shared eligibility adds canonical hashing and metadata columns to projection
writes, preserving structural predicates and identity-before-binding lock order;
eligibility reads now precede binding locks. Query/lock/SQL allocation costs remain
named delegated variables, not constant-time claims. Bounded native preview samples
at M=1/8/32 members and I=1 verified identity plus row/DML oracles document the
mechanism, not matched latency, production SLO or broad scale admission. No
speculative index, optimization or benchmark driver was introduced.

Other-role projection, profile/doctor, broader restart/scale/fault matrices,
full feature/live/fence/compatible rollback and beta
release gates remain open. No permission to deploy or continue into them follows.

## Parent phase admission

Both fresh reviews passed without mandatory corrections. Parent read both and
verified the45-file checkpoint before this docs-only closeout. Historical seal,
proof and pre-closeout documents remain in identity-mapping/closeout. Existing
checks are reused, not rerun; no tested executable bytes changed.

Admission covers only the specified domain-manager service/CLI and its evidence.
It does not establish all-role, matched-scale-performance, live-provider, rollout
or beta admission. Subsequent product units require an explicit parent assignment.
