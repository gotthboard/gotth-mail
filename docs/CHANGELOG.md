# Changelog

All meaningful repository changes must be recorded here in the same commit that makes the change.

This changelog is operator-facing project history, not a replacement for workflow evidence. Entries must be verbose enough that a reviewer can understand what changed without reading the full diff first.

## Rules

- Update this file for every change that modifies product docs, architecture, implementation specs, workflow state, source code, tests, deployment behavior, security posture, or user-visible behavior.
- Use the newest entry at the top of the `Unreleased` section until a release/version tag exists.
- Every entry must include:
  - date and time, including timezone
  - commit identifier
  - affected files
  - verbose explanation of what changed and why
  - verification performed
- Historical entries must use the real commit hash.
- The entry for the commit currently being created cannot contain its final Git hash because Git hashes the changelog content itself. Use `current commit; hash assigned by Git after commit` for that one case, then use real hashes for historical entries.
- Do not record private secrets, credentials, raw tokens, or unredacted before/after values.
- Do not use the changelog as a fake done signal; workflow evidence and verification still live under `workflow/`.

## Unreleased

### 2026-09-19 11:14 CDT — Authenticate automatic-mail authority through final transport

Commit: current commit; hash assigned by Git after commit

Affected files:

- notification SMTP configuration, secret loading, and integration tests
- shared authenticated-identity classification and Postfix gate wiring
- reference Postfix SASL configuration and outbound-policy container smoke
- same-domain hostile-path evidence and changelog

Explanation:

Closed a cold runtime-review defect where signed notification email passed its
initial durable system-sender policy check but submitted unauthenticated SMTP,
leaving the final queue gate unable to recover that authority. Signed email now
requires a CRAM-MD5 SMTP username exactly equal to `system:<from-address>` and a
bounded direct or private-file secret. Submission policy and the final gate use
the same authority classifier. The reference Postfix service authenticates the
exact system ID and permits authenticated relay only after the outbound policy
check. A bounded core restart handles the observed Postgres health/network
startup race without masking persistent failure.

Verification:

- focused development-host normal and race suites passed for webmail,
  notification runtime/plugin, daemon, gate, and outbound policy
- a throwaway real Postfix/Cyrus spike proved colon-bearing durable IDs survive
  SMTP AUTH into the queued `sasl_username` attribute
- the rebuilt reference stack rejected the restricted system sender, then
  admitted it after explicit policy change through both SMTP submission and
  final transport, with exactly one captured relay
- repository-wide tests passed inside the rebuilt container image

Risks / non-goals:

- no live queue, domain policy, deployment, production credential, tag,
  release, or external service changed

### 2026-09-19 10:40 CDT — Preserve admitted authority through final relay

Commit: `767d62e`

Affected files:

- Postfix gate authority classification and tests
- reference forward fixtures, map generation, and container smoke
- same-domain hostile-path evidence and changelog

Explanation:

Closed the post-spoofing-repair transport seam without trusting envelope text.
The final gate now maps an authenticated `system:` SASL identity to the durable
system-sender authority class while ordinary SASL identities remain mailbox
authorities, and rejects ambiguous dual authority. The container proof now
releases and relays the same inbound forwarded message instead of injecting a
new unauthenticated local message. Its reference alias expands to two external
recipients, and the in-memory map fixture and SQL admission fixture now agree.

Verification:

- focused development-host normal and race suites passed for the affected
  commands and policy packages
- the rebuilt reference stack held the two-recipient inbound forward, rechecked
  and explicitly released it, then accepted exactly one two-recipient SMTP
  transaction
- the smoke emits queue, transport, and sink diagnostics on cardinality failure

Risks / non-goals:

- no live queue, domain policy, deployment, production credential, tag,
  release, or external service changed

### 2026-09-19 10:29 CDT — Reject spoofed inbound envelope authority

Commit: `0b0e9e4`

Affected files:

- outbound queue admission and hostile-path tests
- same-domain hostile-path evidence and changelog

Explanation:

Closed a repaired-tree cold-review finding. Queue admission no longer turns an
unauthenticated inbound `MAIL FROM` that happens to equal a hosted mailbox into
an authoritative local envelope-sender source. Only authenticated mailbox or
durable system-sender bindings can contribute sender authority; inbound
forwarding is governed by the authoritative expansion objects that actually
caused it. This prevents a spoofed local reverse path from injecting an
unintended governing domain and holding legitimate forwarded mail.

Verification:

- new PostgreSQL coverage proves a spoofed hosted mailbox reverse path adds no
  envelope-sender provenance while chained alias/forward sources remain intact
- focused development-host normal and race suites passed for outbound policy

Risks / non-goals:

- no live queue, domain policy, deployment, production credential, tag,
  release, or external service changed

### 2026-09-19 10:17 CDT — Expose policy administration and verify restored mailbox state

Commit: `86fb764`

Affected files:

- `internal/api/outbound_policy.go` and API coverage
- `internal/outboundpolicy/admin.go`, backup verification, and corruption tests
- same-domain hostile-path evidence and changelog

Explanation:

Closed two first-pass cold-review defects. The SQL-authoritative policy
preview/apply service is now reachable through bounded authenticated API
routes. Both routes require a scoped `domain:admin` token for the selected
domain; apply additionally requires the preview digest and a valid correlation
ID. Restore verification now compares captured mailbox verifier and quota
state as well as identity and enablement, preventing a damaged credential or
quota restore from being reported as verified.

Verification:

- new API coverage proves unauthenticated preview is rejected and a scoped
  token can preview and confirm an exact revision-bound policy change
- new PostgreSQL corruption coverage proves verifier and quota drift both fail
  restore verification
- focused development-host normal and race suites passed for API, outbound
  policy, and operations

Risks / non-goals:

- no live domain policy, queue, deployment, production credential, tag,
  release, or external service changed

### 2026-09-19 10:00 CDT — Preserve whole-message multi-recipient delivery

Commit: `5bfea95`

Affected files:

- Postfix reference and rendered transport configuration
- outbound queue admission validation and gate tests
- reference SMTP sink, container smoke, evidence, and changelog

Explanation:

Removed the single-recipient limit from the final policy transport. Postfix
`pipe(8)` expands recipient-bearing command arguments once per recipient, so
the old limit invoked the gate once per recipient while each invocation
inspected and relayed the entire queue recipient set. An allowed
multi-recipient message could therefore be duplicated. One pipe request now
carries every paired original/final recipient for the message. Core admission
also rejects any delivery argument set whose canonical final recipients do not
exactly match the independently inspected queue set.

Verification:

- focused development-host normal and race suites passed for outbound policy,
  the Postfix gate, rendered configuration, and gate command
- the rebuilt reference stack accepted exactly one SMTP transaction containing
  both recipients after the complete hold/release path passed
- shell syntax and `git diff --check` passed

Risks / non-goals:

- no live queue, deployment, production credential, tag, release, or external
  service changed

### 2026-09-19 09:43 CDT — Repair catch-all termination and backup consistency

Commit: `56276ef`

Affected files:

- `internal/outboundpolicy/admission.go` and hostile expansion tests
- `internal/outboundpolicy/backup.go`
- release/restore hostile-path evidence and changelog

Explanation:

Closed two cold-review findings. Wildcard catch-all expansion now stops when
its target is an enabled local mailbox; without that check the catch-all could
incorrectly reapply to its own mailbox target until the depth limit. Exact
aliases still take precedence and missing local recipients still use the
catch-all. Backup capture now reads domains, mailboxes, aliases, system
senders, queue parents, recipients, and sources under one repeatable-read,
read-only transaction so the artifact cannot combine unrelated points in time.

Verification:

- new PostgreSQL coverage proves a catch-all to a local mailbox terminates with
  exactly one catch-all provenance source
- focused development-host normal and race suites passed for outbound policy
  and operations/restore
- `git diff --check`

Risks / non-goals:

- no live queue, deployment, production credential, tag, release, or external
  service changed

### 2026-09-19 09:35 CDT — Serialize policy authority across queue release

Commit: `6228db6`

Affected files:

- `internal/outboundpolicy/decision.go`
- `internal/outboundpolicy/release.go`
- `internal/outboundpolicy/release_test.go`
- release/restore hostile-path evidence and changelog

Explanation:

Closed a release-time authorization race found during cold review. A confirmed
release previously recomputed current policy before invoking Postfix, but a
concurrent domain, mailbox, alias, or system-sender mutation could commit after
that check and before `postsuper -H`. Release now holds PostgreSQL share locks
on every policy-authority table from the final confirmation recheck through
Postfix release, live metadata verification, and durable completion. Ordinary
policy and identity mutations therefore wait; concurrent releases may still
proceed because their locks are compatible.

Verification:

- a PostgreSQL concurrency test pauses inside the external release boundary,
  proves a domain policy update cannot commit, resumes release, and proves the
  verified release completes
- focused development-host normal and race suites passed for outbound policy
- `git diff --check`

Risks / non-goals:

- release is rare and deliberately prioritizes authorization correctness over
  concurrent policy-administration throughput
- no live queue, deployment, production credential, tag, release, or external
  service changed

### 2026-09-19 09:28 CDT — Complete outbound release, recovery, and hostile-path enforcement

Commit: `be5108a`

Affected files:

- outbound policy release, backup/restore, automatic-mail, and expansion logic
- daemon and Postfix helper authorization boundaries
- webmail draft persistence and To/CC/BCC submission enforcement
- database migrations `0010` and `0011`
- reference Compose/Postfix configuration and outbound-policy smoke
- same-domain feature evidence and changelog

Explanation:

Added explicit release preview and confirmed release for policy-held Postfix
messages. The confirmation binds immutable queue identity and every current
governing scope/revision; release serializes on the queue, audits intent before
`postsuper -H`, verifies live metadata afterward, records visible retry errors,
and is idempotent after a verified release. Release uses an independent bearer
credential that is unavailable to Postfix pipe services. The ordinary delivery
helper credential cannot preview or invoke release, and the release credential
cannot register or reconcile delivery work.

Extended backup artifacts and isolated SQL restore to preserve and verify
domain policy, immutable mailbox/alias/system-sender identities, and durable
queue provenance and hold state. Webmail drafts now persist CC and BCC; submit
resolves To/CC/BCC atomically before signing or SMTP, includes BCC only in the
SMTP envelope, and never emits a Bcc header. Rejected submissions now write a
bounded address-free audit event. Automatic notification, autoresponder, DSN,
and bounce outcomes share one closed policy disposition and never generate a
second bounce.

Expansion provenance now distinguishes ordinary aliases, one-to-many lists,
external forwards, and wildcard catch-alls from the authoritative alias graph.
Exact aliases take precedence over catch-alls. The real container smoke now
accepts an inbound local forward, holds its forbidden external expansion,
changes policy, previews and explicitly releases it, and then proves an
unrestricted message crosses the final gate into a real SMTP capture socket.

Verification:

- focused local tests passed for daemon, Postfix gate, outbound policy, and
  both runtime commands
- focused development-host PostgreSQL suites passed for outbound policy,
  notification runtime, Postfix gate, webmail, operations, migrations, API,
  daemon, and runtime commands
- container smoke proved credential separation, absence of the release secret
  from Postfix import/export environments, inbound-forward hold, idempotent
  recheck, audited confirmed release, and allowed final SMTP relay
- migration parity, isolated restore, retry/replay, mixed-recipient, stale
  confirmation, release-helper failure, and BCC non-disclosure tests passed
- `git diff --check`

Risks / non-goals:

- no live queue was changed; all Postfix release and relay evidence used an
  isolated disposable reference Compose project
- final repository-wide race/vet/build gates and the two-pass cold admission
  review remain before the feature is marked done
- no deployment, DNS, production credential, tag, published release,
  product-main merge, or external message occurred

### 2026-09-19 08:45 CDT — Wire Postfix submission and final transport enforcement

Commit: `a0ac228`

Affected files:

- `cmd/gotth-mail/`, `cmd/gotth-mail-postfix-gate/`, and daemon HTTP wiring
- `internal/outboundpolicy/` and `internal/postfixgate/`
- reference Postfix image, `main.cf`, `master.cf` fragment, and Compose wiring
- generated render contract, container smoke, feature evidence, and changelog

Explanation:

Replaced the reference stack's decorative policy configuration with an actual
submission and final-transport gate. Authenticated RCPT requests now resolve
the complete reachable SQL alias graph and evaluate every leaf atomically;
forbidden leaves reject before queue admission, while cycles, excessive
fan-out, ambiguous rows, and unavailable authority defer closed. Unauthenticated
mail remains under Postfix relay and local-recipient controls.

Postfix now uses long queue IDs and a dedicated pipe(8) transport. The gate
inspects the live queue, registers immutable SQL-authoritative provenance,
re-evaluates every remaining recipient under current policy, reconciles a
whole-message hold before returning a temporary failure when policy forbids a
delivery, and only then hands an allowed message to the configured relay. A
separate authenticated helper exposes only bounded queue inspection and hold;
it does not expose a shell, arbitrary `postsuper` selector, delete, or release.

The reference Compose stack now builds the gate into a Postfix-side image,
waits for PostgreSQL health, seeds an explicit same-domain fixture, exports
only the required environment into Postfix services, and renders the same
long-ID and policy-transport contract used by the runtime.

Verification:

- development-host focused PostgreSQL tests passed for outbound policy,
  Postfix gate, daemon, core command, and gate command
- repository-wide serial tests, focused race tests, `go vet ./...`, and builds
  of all four commands passed on the development host
- reference `docker compose config` and the containerized outbound-policy
  smoke passed; an injected forbidden message was assigned a long queue ID,
  held as a whole message, persisted as `held`, rechecked idempotently, and
  emitted exactly one hold-applied audit event
- hostile unit coverage includes alias chains, unproven expansion, reachable
  cycles, malformed policy requests, helper authentication, metadata failure,
  all-recipient recheck, and relay suppression
- `git diff --check`

Risks / non-goals:

- this remains an in-progress feature checkpoint; explicit release,
  diagnostics, restore proof, allowed-relay container proof, BCC/list/catch-all
  coverage, and remaining automatic-message paths are still open
- no live queue was held or released and no deployment, DNS, credential, tag,
  release, product-main merge, or external message occurred

### 2026-09-19 08:15 CDT — Add durable outbound queue enforcement boundaries

Commit: `860b97f`

Affected files:

- `migrations/0009_outbound_queue.sql` and embedded migration parity
- `internal/outboundpolicy/`
- daemon, webmail, notification, and plugin policy wiring
- reference Compose configuration and focused contract tests
- same-domain feature evidence and changelog

Explanation:

Added durable queue provenance, immutable authoritative source identities,
policy-revision snapshots, whole-message hold state, and idempotent hold
reconciliation. Queue registration binds a strict Postfix long queue ID to an
arrival fingerprint, canonical envelope sender, complete remaining-recipient
set, and authoritative local source object IDs. A reused or changing queue ID,
missing source, corrupt state, or policy uncertainty now fails closed.

Added a narrow Postfix boundary that reads bounded `postqueue -j` JSON Lines,
derives and rechecks arrival identity, and can invoke only
`postsuper -h <validated-long-queue-id>` without a shell. The reconciler locks
one queue message, records intent before the external helper, verifies metadata
before and after the hold, records retryable reconciliation errors, and never
claims a partial database/external command transaction.

Submission decisions now resolve authenticated mailboxes, admitted envelope
senders, durable system senders, and expansion objects from PostgreSQL rather
than accepting caller-supplied governing domains. Transport decisions ignore
caller authority, reload immutable queue provenance, re-evaluate current policy
revisions, and mark newly forbidden messages for a policy hold. Activation
preview now includes durable queued-recipient impact and refuses unresolved
active sources.

Webmail rejects the complete draft before signing or SMTP if any recipient is
forbidden. Signed-email notifications use a durable system-sender identity,
suppress policy-blocked delivery without generating another message, and defer
when policy is unavailable. The standalone notification plugin calls the
bounded internal policy endpoint. The daemon exposes the same closed decision
contract and rejects caller-supplied authority fields.

Verification:

- `go test -p=1 ./internal/notifyruntime ./cmd/gotth-mail-plugin ./cmd/gotth-mail ./internal/outboundpolicy ./internal/daemon ./internal/render ./internal/webmail ./internal/store -count=1`
- `go vet` passed for the same packages
- `go test -p=1 ./... -count=1`, repository-wide `go vet ./...`, and builds
  of all three commands passed on the development host
- focused race tests passed for the changed runtime packages and commands
- PostgreSQL tests cover registration identity, immutable provenance, source
  resolution, transport re-evaluation, activation races, audit atomicity, and
  hold reconciliation success/failure/idempotence
- command-boundary tests cover fixed executable names/arguments, output bounds,
  malformed/changing queue data, helper failure, and metadata mismatch
- `git diff --check`

Risks / non-goals:

- this remains an in-progress checkpoint; actual generated Postfix policy and
  final-transport wiring, container queue proof, explicit release, diagnostics,
  restore proof, and the full hostile-path matrix are still open
- no live queue was held or released and no deployment, DNS, credential, tag,
  release, product-main merge, or external message occurred

### 2026-09-19 07:00 CDT — Start same-domain outbound enforcement

Commit: `50d618d`

Affected files:

- `internal/outboundpolicy/`
- `internal/store/store.go` and migration parity tests
- `migrations/0008_outbound_policy.sql`
- `go.mod`
- workflow state, event ledger, coverage evidence, and changelog
- same-domain feature status README

Explanation:

Started the owner-priority alpha blocker in its dedicated durable worktree.
The new policy core normalizes domains with an explicit non-transitional UTS
#46/IDNA2008 lookup profile, discards the library's documented partial result
on every conversion error, compares exact lowercase A-labels, and fails closed
when authority, scope, revision, stage, recipient, or transport queue identity
is unavailable. Submission mismatches reject; transport mismatches defer for a
policy hold; conflicting restricted governing domains reject.

Added the compatibility-preserving PostgreSQL domain policy migration. Existing
and new rows remain `unrestricted` at revision `1`; closed enum and positive
revision constraints reject corrupt state. Added serializable, revision- and
digest-bound preview/apply administration. Preview currently reports bounded
alias and external-target counts, not addresses; queued-recipient counting is
still open. Apply re-reads and locks current state, rejects stale, malformed,
or oversized confirmation, increments the revision atomically, and includes
the confirmation digest and counts in the atomic redacted audit. Audit failure
rolls back; commit failure is returned without claiming success.

The live identity feature is now honestly `blocked`, not complete: its
remaining proof requires a deployed public endpoint. The single active
workflow slot advances to this feature under Danny's instruction to finish the
alpha; that instruction does not silently authorize deployment.

Verification:

- clean baseline `go test ./...`
- expected-red focused tests before each production unit
- `go test ./internal/outboundpolicy -count=1`
- `go test ./internal/store -count=1`
- `go test -race ./internal/outboundpolicy ./internal/store -count=1`
- `go vet ./internal/outboundpolicy ./internal/store`
- `go test -p=1 ./... -count=1`
- PostgreSQL upgrade/default/constraint, stale-confirmation, and atomic
  audit-rollback tests passed
- runtime contract inspected against Go 1.26.6 and `golang.org/x/net` v0.56.0
- Postfix long queue-ID alphabet and shape checked against the official
  `postconf(5)` manual

Risks / non-goals:

- this is an in-progress foundation batch, not feature completion
- queue metadata/hold reconciliation, daemon wiring, submission and expansion
  enforcement, automatic mail, diagnostics, backup/restore, and container
  evidence remain open
- no deployment, DNS, credential, tag, release, product-main merge, or live
  mail mutation occurred

### 2026-09-15 10:56 CDT — Prioritize same-domain-only outbound mail

Commit: current commit; hash assigned by Git after commit

Affected files:

- v1 mail-core and 1.0 release PRD, architecture, and implementation contracts
- README blocker summary and coverage posture
- workflow dependency graph, feature plan, and event ledger

Explanation:

Added the owner-prioritized per-domain `same_domain_only` outbound policy as a
first-class 1.0 workstream. The contract derives governing domains from the
authenticated mailbox, admitted envelope sender, system identity, and local
expansion sources, closing delegated send-as and inbound-forwarding bypasses.
It uses exact normalized SMTP envelope domains, leaves inbound mailbox delivery
independent, and covers SMTP, webmail/API, recipient expansion, automatic mail,
queued retry/replay/restore, and final Postfix transport. Policy uncertainty
defers rather than permitting delivery. Enabling the restriction
requires a revision- and digest-bound preview/confirm flow. Because Postfix has
no honest per-recipient hold primitive, an affected queued recipient places the
whole queue message on a visible policy hold; this may delay allowed recipients
but does not delete or automatically release the message.

The active live-identity workstream remains unchanged. This feature is marked
high priority as the next implementation assignment after that boundary, and
alpha integration now depends on it.

Verification:

- `git diff --check` passed
- `workflow.toml` parsed successfully; IDs, roots, dependencies, priority,
  active-feature preservation, and workflow feature paths were checked
- every `workflow.events.jsonl` line parsed as a JSON object
- executable product and deployment verification remain future planned work

Risks / non-goals:

- no runtime code, mail configuration, queue mutation, deployment, credential,
  tag, release, or product-main merge

### 2026-09-13 23:07 CDT — Plan the host-owned Extensions administrator

Commit: current commit; hash assigned by Git after commit

Affected files:

- 1.0 and operations/admin PRD, architecture, and implementation contracts
- workflow dependency graph and planned feature records

Explanation:

Added Danny's requirement for one GOTTH Mail administrator surface that lists
all installed extensions and supports setup, bounded testing, enable/disable,
updates, audit, versions, and rollback. The browser remains connected only to
Mail; extension processes cannot inject markup, scripts, templates, styles, or
actions. Mail retains registry, authorization, CSRF/confirmation, encrypted
write-only secrets, grants, transport identity, supervision, mutation, audit,
and rollback authority.

The plan places immutable `gotth-extensions` foundation adoption before the UI
and requires every concrete mechanism to remain independently packaged in a
`gotth-extension-<slug>` repository. Alpha integration now depends on both
planned units.

Verification:

- `git diff --check` passed
- `workflow.toml` parsed successfully; feature IDs, roots, dependencies, and
  workflow feature directories are complete and consistent
- every `workflow.events.jsonl` line parsed as a JSON object
- implementation and runtime verification remain future planned work

Risks / non-goals:

- no runtime code, provider repository, product integration, credential, DNS
  mutation, deployment, tag, release, or mirror change

### 2026-09-13 20:23 CDT — Record SCIM token bootstrap verification

Commit: current commit; hash assigned by Git after commit

Affected files:

- SCIM token bootstrap evidence
- identity coverage map
- workflow event ledger
- `docs/CHANGELOG.md`

Explanation:

Recorded the verified operator credential boundary and reconciled the stale
coverage row that still claimed the new live OIDC issuer returned 404. The
evidence names the exact PostgreSQL, race, full-tree, build, module, profile,
shell, negative-path, and coverage results and keeps the missing deployment and
live SCIM provider explicit.

Verification:

- development-host focused PostgreSQL and race suites: pass
- development-host full tests and full race tests: pass
- vet, all command builds, module verification, pinned Authentik profile,
  shell syntax, clean-tree, and diff checks: pass
- `internal/scimtoken` coverage: 89.7%, with non-injected defensive system
  error branches documented rather than hidden

### 2026-09-13 20:20 CDT — Extend SCIM token negative coverage

Commit: `7fb2a03`

Affected files:

- SCIM token protected-file and service tests
- `docs/CHANGELOG.md`

Explanation:

Extended the hostile matrix across missing paths, control bytes, absent or
closed databases, invalid actor IDs, and weak secrets for both preview and
apply. These are negative-path tests only; runtime behavior and authority did
not broaden.

Verification:

- focused coding-host tests and `git diff --check`: pass
- development-host PostgreSQL, race, and coverage rerun remains required

### 2026-09-13 20:16 CDT — Reject corrupt SCIM token state

Commit: `e194203`

Affected files:

- SCIM token planner and failure-path tests
- identity/provisioning PRD and implementation contract
- `docs/CHANGELOG.md`

Explanation:

Cold review found that a malformed stored verifier was indistinguishable from
a valid verifier that did not match the requested secret. That would let an
operator rotation silently overwrite corrupt state. The planner now validates
the stored PBKDF2 structure first and fails closed, and an update must report
exactly one affected row before audit and commit.

Verification:

- focused coding-host tests and `git diff --check`: pass
- real PostgreSQL and race rerun on the development host remains required

### 2026-09-13 20:14 CDT — Harden SCIM token file ownership and CLI proof

Commit: `f23c475`

Affected files:

- SCIM token implementation and PostgreSQL tests
- `gotth-mailctl` end-to-end command test
- identity/provisioning architecture and implementation contract
- `docs/CHANGELOG.md`

Explanation:

Tightened the protected-file boundary after cold review: the SCIM bearer file
must now be owned by the command's effective user in addition to being regular,
non-symlink, and inaccessible to group/world. Added an end-to-end CLI test that
executes preview and apply through a real migrated PostgreSQL database, verifies
that output contains neither secret nor path, and confirms verifier plus audit
admission. Malformed stored verifiers now fail closed, and credential updates
must report exactly one affected row. Removed an unnecessary test-only hash
operation.

Verification:

- focused coding-host tests and `git diff --check`: pass
- real PostgreSQL rerun on the development host remains required

### 2026-09-13 20:12 CDT — Implement transactional SCIM client-token admission

Commit: `c3f13b8`

Affected files:

- `internal/scimtoken/scimtoken.go`
- `internal/scimtoken/scimtoken_test.go`
- `internal/identity/identity.go`
- `cmd/gotth-mailctl/main.go`
- `cmd/gotth-mailctl/main_test.go`
- `docs/CHANGELOG.md`

Explanation:

Added the operator-only `gotth-mailctl identity scim-token preview|apply`
mechanism needed to bootstrap or rotate Authentik's outbound SCIM bearer.
Secrets are accepted only from bounded owner-only regular files opened without
following a final symlink. Preview output contains only a confirmation digest,
stable actor ID, and operation. Apply locks and rechecks current state inside a
serializable PostgreSQL transaction, stores only a PBKDF2 verifier, and commits
the redacted audit event atomically. Stable actor and storage IDs survive
rotation, while a same-secret retry performs no database or audit write.

No Authentik object, live token, deployment, public URL, product-main ref, tag,
or release changes in this implementation commit.

Verification:

- focused package tests and vet on the coding host: pass (PostgreSQL cases skip
  there because local `initdb` is intentionally absent)
- `git diff --check`: pass
- full PostgreSQL and heavy development-host verification remains required
  before admission

### 2026-09-13 20:05 CDT — Specify SCIM bearer bootstrap and rotation

Commit: `5705cd4`

Affected files:

- identity/provisioning PRD, architecture, and implementation contract
- live Authentik workflow contract and verification manifest
- `docs/CHANGELOG.md`

Explanation:

Specified the missing operator mechanism required before Authentik can call the
GOTTH Mail SCIM endpoint. The command is a preview/confirm transaction that
accepts a bearer only through an owner-only regular file, stores only a
verifier, audits mutation atomically, preserves the stable actor-derived SCIM
scope across rotation, and makes same-secret retry a no-op. The contract
forbids argv/environment secret input and secret, verifier, digest, or path
disclosure in plan output and audit.

This is a local credential-bootstrap contract. It does not create the live
Authentik SCIM provider, deploy GOTTH Mail, choose a public URL, retire the
historical provider, or claim the lifecycle gate complete.

Verification:

- requirement/architecture/implementation/workflow trace review: pass
- `git diff --check`: pass

### 2026-09-13 19:50 CDT — Admit and stage the live GOTTH Authentik profile

Commits: `d7fdb56`, `c783440`, `f6d971a`; current commit hash assigned by Git
after commit

Affected files:

- identity/provisioning PRD, architecture, implementation contract, feature
  plan, component adoption record, and live evidence
- `deploy/authentik/gotth-mail/manifest.json`
- `deploy/authentik/gotth-mail/blueprint.yaml`
- `scripts/verify-authentik-profile.sh`
- `workflow.events.jsonl`
- `docs/CHANGELOG.md`

Explanation:

Admitted MIT-licensed `gotth-authentik` revision
`77c811c18fe3c107f6f3e97ce3f9a3850a685300` as the build-time renderer for
the GOTTH Mail OIDC provider/application, verified-email enrollment, and
application access group. The component is not a runtime dependency or remote
controller. GOTTH Mail retains live apply/rollback, generated-secret transfer,
membership, SCIM provider, and product authorization ownership.

The migration is additive: `gotth-mail` was created beside
`gophermailforge`, whose objects and database snapshot remain the rollback
path. `gotth-mail-users` gates application entry only and grants no product
role. The current loopback callback remains a pre-production smoke target;
public HTTPS callback, browser code redemption, SCIM lifecycle, restart,
backup, restore, and final old-provider retirement remain blocked gates.

Verification:

- pinned local profile render/check, dirty-checkout rejection, and secret-field
  scan: pass
- Authentik 2026.5.2 rollback-only importer transaction: pass
- root-only PostgreSQL custom-format backup and `pg_restore --list`: pass
- additive live import and idempotent re-import: pass
- generated confidential client secret retained across re-import: pass
- exact new issuer discovery, JWKS, authorization redirect/state, enrollment,
  and end-session probes: pass
- historical issuer remains HTTP 200 and live containers remain healthy
- development-host full tests, race tests, vet, all three command builds,
  module verification, shell syntax, clean-tree, and diff checks: pass
- browser callback remains blocked because no GOTTH Mail runtime is deployed
  at the strict loopback callback
- Authentik SCIM lifecycle remains blocked because the live installation has
  no SCIM provider and no deployed GOTTH Mail SCIM endpoint

### 2026-09-13 19:18 CDT — Reconcile the GOTTH-wide MIT decision

Commit: current commit; hash assigned by Git after commit

Affected files:

- GOTTH component adoption contract
- identity/provisioning PRD and architecture
- live Authentik feature contract
- `docs/CHANGELOG.md`

Explanation:

Danny selected MIT for all owner-authored GOTTH repositories. The adoption
record now pins the newly admitted `gotth-authentik`, `gotth-pg-migrate`,
`gotth-release`, and `gotth-infrastructure` revisions and removes stale
current-state licensing blockers. Licensing is not dependency admission:
components still require applicable mechanisms, exact consumer evidence, and
release review. Third-party dependencies and assets retain their own licenses.

The live Authentik issuer migration remains separately gated. This
documentation change grants no live-mutation authority and changes no runtime,
tag, release, deployment, or product-main state.

Verification:

- all seventeen Forgejo and GitHub `main` refs match exactly
- all seventeen canonical repositories expose a standard MIT `LICENSE`
- current-state identity and component-allocation statements agree
- `git diff --check`

### 2026-09-13 19:06 CDT — Specify the GOTTH Mail classic interface language

Commit: current commit; hash assigned by Git after commit

Affected files:

- webmail product requirements, architecture, implementation, and verification
- administration-shell requirements, architecture, and implementation guidance
- shared classic-interface reference
- repository documentation index
- canonical v4 workflow state, verification gates, and requirement evidence
- `docs/CHANGELOG.md`

Explanation:

Recorded Danny's requirement that the custom GOTTH Mail webmail use an Outlook
Classic-inspired but distinctly GOTTH Mail presentation. The contract now
requires a desktop-first three-pane workflow, dense sortable message list,
configurable and resizable reading pane, traditional command bar, keyboard
navigation, context-menu parity, responsive mobile drill-down, and restrained
blue/gray light and dark themes shared appropriately with the separate admin
GUI. It explicitly preserves the server-rendered Go, templ, Tailwind, and HTMX
boundary; existing security, accessibility, hostile-content, and
control-plane-authority invariants; and forbids copying Microsoft trademarks,
copyrighted assets, or exact branding. The canonical v4 workstream remains
`in_progress`; the docs change does not misrepresent the existing minimal
`/webmail` shell as satisfying the new interface contract.

Verification:

- reviewed requirement trace across PRD, architecture, implementation,
  acceptance criteria, workflow state, verification gates, shared reference,
  evidence, and docs index
- `go test ./internal/webmail`: pass
- `git diff --check`: pass

### 2026-09-13 18:45 CDT — Close opaque SCIM Group evidence

Commit: `270572fbeab7c24e187984658351a277fd30b578`

Affected files:

- identity implementation consistency repair
- release-line architecture and implementation status
- global coverage map
- opaque-Groups workflow state and evidence
- `docs/CHANGELOG.md`

Explanation:

Closed the non-authoritative Group slice after PostgreSQL, full, race, vet,
build, module, coverage, graph, and cold-review gates passed. Removed one stale
implementation sentence that still claimed Groups were unavailable and made
the remaining boundary explicit: Groups are durable provisioning inventory,
but only a separately admitted stable Authentik Group-to-role projection may
create product authority.

Verification:

- focused PostgreSQL Group lifecycle and schema-integrity tests twice: pass
- full repository tests and race tests at `a74ad3e`: pass
- vet, all command builds, module verification, and diff checks: pass
- changed Group membership projector coverage: 80.4%
- code-only Graphify extraction: 1,805 nodes / 4,472 edges; SHA-256
  `1d52d9d1b75218c2c845f0de6e818a987c57e7231c436e5e7589aa988dbe4313`

### 2026-09-13 18:43 CDT — Prove database-enforced Group edge integrity

Commit: `772bf08716aed3c9f47aab771482f97eaa784da1`

Affected files:

- SCIM Group PostgreSQL lifecycle test
- `docs/CHANGELOG.md` (recorded by the evidence-closure commit)

Explanation:

Added direct PostgreSQL proof that normalized membership cannot cross a SCIM
scope and cannot use a Group resource where a User resource is required. This
tests the composite foreign-key contract independently of HTTP validation.

Verification:

- exact Group PostgreSQL test twice: pass

### 2026-09-13 18:38 CDT — Report referenced User deletion as a SCIM conflict

Commit: `a74ad3eaf988556fa93d2db36c132639aac1eb82`

Affected files:

- product SCIM PostgreSQL adapter
- `docs/CHANGELOG.md` (recorded by the evidence-closure commit)

Explanation:

The first PostgreSQL run proved storage rollback but exposed a bad protocol
boundary: deleting a User still referenced by a Group returned generic 500.
The adapter now detects that reference before projection and reports an exact
409 conflict; a concurrent database foreign-key conflict maps to the same safe
protocol class.

Verification:

- exact Group lifecycle, rollback, store-conformance, and migration tests
  twice: pass
- full repository tests and race tests: pass

### 2026-09-13 18:35 CDT — Enable opaque non-authoritative SCIM Groups

Commit: `b7023dd26b7fab1e7d49e5a16b7ad97753984361`

Affected files:

- identity/provisioning PRD, architecture, implementation, and GOTTH adoption contract
- workflow manifest and opaque-Groups feature record
- SCIM HTTP composition and product PostgreSQL projection
- migration `0007_scim_group_members` and parity checks
- SCIM Group lifecycle, isolation, conflict, authority, and rollback tests
- `docs/CHANGELOG.md`

Explanation:

Enabled the pinned `gotth-scim` Group protocol surface after adding the
missing product constraint: every member is a live opaque User ID in the same
provisioning scope. Normalized membership is replaced atomically with the
Group resource and audit, Group deletion cascades its edges, and User deletion
is restricted while referenced. Nested, missing, cross-scope, and duplicate
members fail closed. Group storage is deliberately non-authoritative; it does
not create product role bindings or trust OIDC group claims.

Verification:

- constrained store/SCIM/API compilation: pass
- PostgreSQL lifecycle, migration, and rollback: pass after the referenced-User
  conflict repair at `a74ad3e`
- `git diff --check`: pass

### 2026-09-13 18:25 CDT — Add reviewed legacy mailbox adoption

Commit: `6f7f4703cb6bd1e68c3b54754b220e3db717a363`

Affected files:

- identity/provisioning PRD, architecture, implementation, and GOTTH adoption contract
- workflow manifest and legacy-adoption feature record
- `internal/identityadopt` preview/apply service and PostgreSQL tests
- `internal/scimstore` transaction-local legacy mailbox claim
- `gotth-mailctl identity adopt` preview/apply commands and parser tests
- `docs/CHANGELOG.md`

Explanation:

Added an explicit path for moving an existing email-keyed mailbox under opaque
SCIM ownership without guessing identity provenance. The operator reviews a
redacted deterministic plan and confirms its exact digest. Apply delegates
User validation, manager reconciliation, and opaque resource-ID generation to
the pinned `gotth-scim` library, while the product SQL adapter locks and
preserves the existing mailbox UUID, verifier, enabled state, creation time,
and mail ownership. It creates no OIDC identity, session, or role authority;
the verified `gotth-oidc` callback remains the only binding path.

Verification:

- constrained package compilation and CLI parser tests: pass
- repeated PostgreSQL adoption, rollback, and restart tests: pass
- full repository tests at `7098b7d`: pass
- final targeted race tests at `1dbda59`: pass
- full repository race tests at `7098b7d`: pass
- vet, all command builds, module verification, and diff checks: pass
- adoption package coverage: 79.8%; changed SQL adoption branches exercised
  through cross-package PostgreSQL tests (remaining uncovered lines are
  defensive database/encoder failures, not an accepted functional gap)
- code-only Graphify extraction: 1,800 nodes / 5,388 edges; SHA-256
  `13fde2b740fbec1f8a787400dca7082c2d640368d3837f2bb640958697d5212b`
- `git diff --check`: pass

### 2026-09-13 18:02 CDT — Reconcile identity evidence and live provider status

Commit: `5c5f27fea44244145bc91479ba2b8d7523296f76`

Affected files:

- root blocker summary and GOTTH component adoption reference
- identity coverage map and current live-binding evidence
- historical blocker supersession marker
- `docs/CHANGELOG.md`

Explanation:

Replaced stale pre-rename and pre-library-adoption status with the verified
current boundary. The documents now record durable OIDC-to-SCIM binding,
transactional session invalidation, session-bound app-password self-service,
the full/race/PostgreSQL gates, focused coverage, and the code graph. Public
provider probes are recorded without bluffing: the desired `gotth-mail`
issuer returns 404 while the historical GopherMailForge issuer remains live.

Verification:

- documentation reconciled against source, tests, PostgreSQL results, public
  discovery responses, and the code-only Graphify artifact
- `git diff --check`: pass

### 2026-09-13 18:01 CDT — Remove unavailable self-service link

Commit: `846683cdef79b0a4c2ad667492c9486f2f40586d`

Affected files:

- runtime/UI session composition
- administrator-page availability rendering and regressions
- `docs/CHANGELOG.md`

Explanation:

Cold review found that an unconfigured runtime advertised a link whose handler
was intentionally absent. The page now renders the link only when a durable
identity-session resolver is actually wired and otherwise retains an explicit
unavailable state. The UI also receives the runtime's configured clock so its
session decision cannot drift from the API during deterministic operation or
tests.

Verification:

- constrained focused HTTP UI and command tests pending
- `git diff --check`

### 2026-09-13 18:14 CDT — Close identity transaction failure paths

Commit: `a86e26ce8a51d1d9d1d8f2adf244068fb1d861c1`

Affected files:

- OIDC identity-session PostgreSQL tests
- SCIM/OIDC lifecycle API tests
- `docs/CHANGELOG.md`

Explanation:

Added proof that an audit insertion failure rolls back the identity reference
and session rather than leaving unaudited authority behind. Extended the SCIM
lifecycle proof to establish that re-enabling a mailbox does not revive a
session revoked by deprovisioning; a fresh verified login is required.

Verification:

- focused PostgreSQL-backed authn and API tests remain pending on the
  development host
- `git diff --check`

### 2026-09-13 18:07 CDT — Expose bound app-password self-service

Commit: `556600ba8887b4d52e7cfe3e0f97eebde27cc7f7`

Affected files:

- GOTTH Mail runtime HTTP composition
- session-bound app-password API and browser UI
- CSRF, one-time-secret, and runtime wiring tests
- `docs/CHANGELOG.md`

Explanation:

Wired the browser app-password surface only when the runtime has the durable
OIDC/SCIM identity-session store. The page resolves the mailbox from the
verified bound session rather than user input, requires the separate CSRF
binding for mutations, emits no-store and restrictive CSP headers, and shows a
new app-password secret exactly once. The API now reuses the already-resolved
bound session instead of performing a second database lookup and uses
constant-time CSRF comparison. A runtime without the durable binding continues
to leave the mutation route unavailable.

Verification:

- constrained focused API, HTTP UI, authn, authz, and command tests
- missing-session, missing-CSRF, create, one-time display, verifier redaction,
  and revoke coverage
- full PostgreSQL, race, vet, build, module, and final review gates remain
  pending on the development host

### 2026-09-13 17:48 CDT — Bind OIDC sessions to SCIM mailboxes

Commit: `4dfa56c552413990a8b3137815d6e40c4f0eb168`

Affected files:

- migration `0006_oidc_scim_identity_binding`
- identity session, API authentication, authorization, and SCIM projection
- PostgreSQL migration, binding, lifecycle, CSRF, and authorization tests
- `docs/CHANGELOG.md`

Explanation:

Added the durable composition between the admitted OIDC and SCIM consumers.
The SQL callback path now requires one active SCIM User whose external ID and
mailbox match the verified OIDC subject and email, then commits the identity
reference, foreign-keyed session, and redacted audit together. Bound sessions
receive only same-mailbox app-password authority and browser mutations require
a separate CSRF cookie/header proof. SCIM disable/delete revokes dependent
sessions, and a bound User external ID cannot be reassigned silently.

Verification:

- focused authn/authz/API/SCIM/store tests on the constrained agent host
- `git diff --check`
- full PostgreSQL, race, and complete-tree gates remain pending on the
  development host

### 2026-09-13 17:37 CDT — Reconcile live OIDC/SCIM identity binding

Commit: `df8a7e84c5c490e77d0329a69b5a3f7ba6bc259f`

Affected files:

- identity/provisioning and release PRD, architecture, and implementation specs
- GOTTH component adoption record
- live Authentik feature contract and workflow manifest
- `docs/CHANGELOG.md`

Explanation:

Defined the actual composition point between the admitted `gotth-oidc` and
`gotth-scim` libraries. A verified issuer/subject and email must resolve to one
active SCIM User external ID and mailbox before GOTTH Mail creates a
foreign-keyed session. SCIM deprovisioning must revoke dependent sessions;
same-mailbox app-password browser use requires a separate CSRF secret. The
contract explicitly refuses provider-specific group-claim parsing and leaves
unlicensed `gotth-authentik` outside the build.

Verification:

- `git diff --check`
- contract layers agree on ownership, failure behavior, migration, and live
  evidence still required

### 2026-09-13 17:51 CDT — Record app-password repair verification and review

Commit: `bc9bbf385758141e152c9f9ae41ab794c6d00565`

Affected files:

- current app-password/Dovecot feature evidence
- `docs/CHANGELOG.md`

Explanation:

Recorded the exact reviewed head, GOTTH component allocation, migration and
runtime behavior, PostgreSQL rollback/concurrency proof, full and race suites,
coverage detail and honest gaps, Graphify artifact, cold-review findings, and
remaining live-integration constraints. The old July happy-path record remains
explicitly superseded.

Verification:

- the reviewed `cd172cb4dc2a9a6ff3491073faeba06a7f8f6b16` worktree is clean;
- focused, full, race, vet, three builds, module, diff, PostgreSQL, Graphify,
  and cold-review gates pass as enumerated in the feature evidence.

### 2026-09-13 17:36 CDT — Close app-password validation coverage gaps

Commit: `cd172cb4dc2a9a6ff3491073faeba06a7f8f6b16`

Affected files:

- app-password identity and Dovecot daemon tests
- `docs/CHANGELOG.md`

Explanation:

Added explicit rejection evidence for empty and oversized labels, missing
mailboxes, entropy failure, invalid generated secrets, missing credentials,
and repeated revocation. Added the legacy mixed-case projection-key test so
the new bounded mailbox snapshot preserves normalization userspace instead of
silently rejecting old in-memory fixtures.

Verification:

- focused local identity and daemon tests pass;
- final development-host coverage and race gates remain required on this exact
  test commit.

### 2026-09-13 17:23 CDT — Make live passdb projection race-free and bounded-copy

Commit: `41cc4b3d6afa086ad9037e45d7dd8c1f1ba09535`

Affected files:

- `internal/daemon/daemon.go`
- `internal/identity/identity.go` and concurrency tests
- identity architecture and `docs/CHANGELOG.md`

Explanation:

Cold source review found that the former daemon projection mutated public maps
while concurrent passdb requests cloned them without synchronization. That was
a real concurrent-map panic and stale-auth risk hidden by sequential tests.
The live identity binding now installs a daemon state lock; mailbox and
app-verifier projection writes use it, while passdb takes one coherent snapshot
of only the requested mailbox and its bounded verifier slice. This also removes
the absurd whole-map copy from every authentication attempt.

Verification:

- focused local identity, daemon, API, and command tests pass, including
  concurrent create/revoke projection against passdb readers;
- the development-host race and full gates will be rerun on this exact commit.

### 2026-09-13 17:14 CDT — Serialize app-password creators without transaction aborts

Commit: `2506f7093a4ff5e8679f76f6d6ba01dc6dd074df`

Affected files:

- `internal/identity/identity.go`
- `docs/CHANGELOG.md`

Explanation:

The real PostgreSQL concurrency gate exposed avoidable serialization failures
when several control-plane instances created credentials for one mailbox.
The design already holds that mailbox row through the active-count check and
insert, which is the precise lock needed. Changed the transaction isolation to
read committed and retained the explicit row lock, so creators serialize at
the mailbox boundary without leaking PostgreSQL `40001` aborts to callers.

Verification:

- focused local identity tests pass;
- the failed development-host concurrency gate is being rerun before any
  admission claim.

### 2026-09-13 17:09 CDT — Repair durable app-password and passdb behavior

Commit: `03345463fb6b4879f92f393eef568cb36226733a`

Affected files:

- `internal/identity`, `internal/daemon`, `internal/audit`, `internal/httpui`,
  `internal/store`, and `cmd/gotth-mail`
- migration `0005_app_password_contract` and focused migration/runtime tests
- identity architecture/implementation docs, README, and superseded evidence
- `docs/CHANGELOG.md`

Explanation:

Separated app-password public IDs from human labels in durable storage and
backfilled the old overloaded field without rewriting verifiers. Creation now
holds the mailbox row lock, enforces eight active credentials, and commits the
credential plus normalized redacted success audit in one transaction while
the mailbox row serializes concurrent creators. Revocation uses the same
atomic boundary. Startup rejects an
over-limit persisted verifier set, and the Dovecot path refuses an over-limit
projection rather than performing attacker-controlled PBKDF2 work.

Configured database startup now gives identity and passdb a durable SQL audit
writer. Otherwise-successful mailbox or app-password authentication defers
when that audit write fails. The runtime UI now receives the same configured
identity service as the API, but it no longer leaks mailbox/app-password
metadata or exposes fake SCIM and bearer-header-dependent mutation forms.
Those browser mutations remain unavailable until a verified OIDC session is
authoritatively bound to mailbox and role state.

Verification:

- focused store, identity, daemon, API, command, audit, and UI tests pass on
  the local constrained host;
- PostgreSQL concurrency/rollback, full, race, coverage, build, graph, and
  cold-review gates remain pending on the development host.

### 2026-09-13 17:05 CDT — Reconcile app-password and Dovecot admission contract

Commit: current commit; hash assigned by Git after commit

Affected files:

- identity PRD, architecture, implementation specification, and GOTTH stack
  adoption contract
- app-password feature README and workflow manifest
- `docs/CHANGELOG.md`

Explanation:

Corrected the app-password slice before implementation. The contract now
separates opaque public credential IDs from human labels, bounds active
credentials to eight per mailbox, requires atomic PostgreSQL credential and
success-audit admission, and makes the post-commit Dovecot projection and
startup validation explicit.

The browser contract no longer pretends ordinary HTML forms can provide API
bearer headers or that an in-process mailbox helper is a SCIM test. Until a
verified `gotth-oidc` session is durably bound to mailbox and role state, the
identity UI must remain read-only and direct authorized automation to the
scoped API. The GOTTH adoption record now states exactly why `gotth-oidc` and
`gotth-scim` are relevant and why no unrelated `gotth-*` package belongs in
the synchronous credential path.

Verification:

- documentation and workflow references were reconciled against the current
  runtime, SQL schema, adopted library boundaries, and dependent live
  Authentik feature;
- implementation and full verification remain pending in this feature branch.

### 2026-09-13 16:29 CDT — Adopt gotth-scim with atomic PostgreSQL projection

Commit: `78b11594abdbb89a37c39151cf6a88ebd17ef833`

Affected files:

- `internal/scimstore`, `internal/api`, `internal/identity`, and
  `internal/daemon`
- `cmd/gotth-mail`, migration `0004_scim_resources`, and migration tests
- GOTTH stack reference, identity and release PRD/architecture/implementation
  specifications, README, workflow manifest, and SCIM evidence
- `docs/CHANGELOG.md`

Explanation:

Removed the handwritten runtime SCIM router and delegated SCIM protocol,
validation, ETag, PATCH/search, opaque-ID, tombstone, conformance, and
write-only password mechanics to the exact pinned `gotth-scim` library. Added
a conformant PostgreSQL adapter whose serializable transaction atomically
admits the SCIM resource, ordered indexes, password verifier, mailbox state,
and success audit record. The executable now routes `/scim/` to the API server
and refuses configured SCIM without migrated durable identity storage.

Each durable `scim_client` actor ID derives an opaque storage scope. Passwords
are hashed from bytes into the existing Django PBKDF2-SHA256 verifier contract;
the plaintext and password field are never stored. Opaque resource IDs survive
mailbox rename and restart, while tombstones permanently reserve deleted IDs
and external IDs. A restarted service now binds and rebuilds its daemon/passdb
view and enabled-domain policy from SQL; disabled and unmanaged domains fail
closed instead of being created by provisioning. Mailbox rename also moves
email-keyed app-password ownership atomically, removes the obsolete daemon
entry, and preserves the credentials at the new address across restart.

The documents explicitly retain the honest limits: Groups and SCIM-driven web
session invalidation wait for authoritative Authentik subject binding; legacy
email-keyed mailboxes require an operator-reviewed adoption mapping; and the
current process-local daemon projection admits only one control-plane writer.
Other `gotth-*` components are used only where their licensed public contracts
fit, not imported as branding theater.

Verification:

- `scim.CheckStore` and focused PostgreSQL store/API/runtime/migration/
  identity/daemon tests pass on the development host;
- focused tests cover restart, concurrency, rollback, tombstones, opaque IDs,
  password replacement, routing, malformed input, and explicit Groups
  rejection;
- final full, race, serialized coverage, vet, command-build, module, Graphify,
  and cold-review gates pass as recorded in the feature evidence; admission is
  limited to the unfinished 1.0-alpha development line.

### 2026-09-13 15:48 CDT — Adopt gotth-oidc with protected durable attempts

Commit: `ebdba59a51d157a77acab089ff5c7c3d89835ed9`

Affected files:

- `internal/authn`, `internal/api`, and `cmd/gotth-mail`
- migration `0003_oidc_protected_attempts` and migration tests
- GOTTH stack reference, identity implementation specification, README, and
  identity workflow evidence
- `docs/CHANGELOG.md`

Explanation:

Removed the duplicate GOTTH Mail discovery, JWKS, Authorization Code, token
exchange, and ID-token verifier implementation. The runtime now delegates
those protocol mechanics to the exact pinned `gotth-oidc` library and retains
only the product-owned browser binding, atomic attempt consumption, local
return path, application session, cookie, and identity boundaries.

OIDC login attempts now persist the library's state digest, encrypted nonce,
encrypted PKCE verifier, and authenticated context rather than raw state and
nonce. Migration `0003` intentionally invalidates legacy in-flight attempts,
preserves sessions, and installs fixed-size database checks. Callback
consumption is one conditional update, so concurrent or replayed callbacks
cannot both win; a failed provider exchange leaves the attempt spent.

The executable now opens, pings, migrates, and loads PostgreSQL before enabling
OIDC. OIDC configuration without durable storage fails startup. Database and
client secrets accept mutually exclusive direct or `_FILE` sources, and the
file form avoids placing container secrets in process environment where the
deployment permits it. Authorization-shaped ID-token groups are no longer
trusted; `gotth-oidc` returns identity facts only.

Verification:

- test-first focused authn/store/API/command suites pass locally;
- repository-wide compile-only tests and `git diff --check` pass locally;
- real PostgreSQL migration, restart, concurrent-consume, and runtime wiring
  tests pass on the development host;
- serialized full coverage passes with 93.3% for `internal/authn`; the final
  race suite, vet, all command builds, module verification, and Graphify
  rebuild pass;
- post-fix cold review found no new slice-level blocker; live Authentik
  evidence remains required before the feature can be called complete.

### 2026-09-13 15:27 CDT — Define honest GOTTH stack adoption for identity

Commit: `819c47dbf47d19ec3a7fe750d3d5604f3ec5b16f`

Affected files:

- identity/provisioning PRD, architecture, and implementation specification
- `docs/reference/gotth-stack-adoption.md` and `README.md`
- identity workflow manifest, coverage map, and feature records
- `docs/CHANGELOG.md`

Explanation:

Reconciled the GOTTH Mail 1.0 identity workstream with the actual reusable
GOTTH component contracts. Runtime OIDC must now replace its duplicate
protocol code with the exact pinned `gotth-oidc` API and persist only protected
one-time attempts. Runtime SCIM must replace its handwritten router with the
exact pinned `gotth-scim` server plus a conformant PostgreSQL adapter and
atomic product projection. The documents now define opaque SCIM identity,
restart/concurrency/migration evidence, and the consumer-owned session,
authorization, mailbox, password, audit, and recovery boundaries.

The component inventory also records why unlicensed, placeholder, unrelated,
or mechanism-breaking repositories are not imported merely to increase the
number of `gotth-*` dependencies. `gotth-authentik`, `gotth-pg-migrate`,
`gotth-release`, and `gotth-infrastructure` remain gated by licensing and
separate compatibility work; `gotth-jobs` does not belong in synchronous login
or canonical provisioning acceptance.

The manifest now activates the OIDC adoption feature, and stale feature-folder
claims of completion have been corrected to match canonical `workflow.toml`.
No runtime code, product `main`, tag, release, mirror, or deployment changed in
this documentation prerequisite.

Verification:

- exact public component revisions, package boundaries, license files, and
  exported OIDC/SCIM contracts were inspected;
- Graphify mapped the existing OIDC, session, SCIM, identity, daemon, and API
  dependency surfaces at source revision
  `21b5ff6876624fc0e14532d636f7d12d92d442b6`;
- `git diff --check` and documentation/workflow consistency checks will gate
  this prerequisite commit.

### 2026-09-13 15:21 CDT — Remove remaining hard-coded v0 runtime identity

Commit: current commit; hash assigned by Git after commit

Affected files:

- `internal/version`, `internal/api`, and `internal/plugin`
- `cmd/gotth-mail` and `cmd/gotth-mail-plugin`
- release implementation specification and `docs/CHANGELOG.md`

Explanation:

Cold review found that the first release-contract pass constrained the CLI
version but left the status API reporting `v0-foundation` and the plugin
Version RPC reporting `v0`. Those strings would have kept the false old product
version alive. All executable entry points now reject invalid linked release
identity, and the status API, CLI, and plugin RPC report the same development,
alpha, beta, or stable build identity.

The release workflow now also exposes the identity libraries' unresolved
license decisions as a blocking feature. Compatibility pins are not a license
decision and do not justify fabricated library tags.

Verification:

- focused version, API, plugin, and command tests passed;
- full and race test suites, vet, all command builds, linked version checks,
  invalid-version startup rejection, shell syntax, reference Compose
  rendering, workflow manifest/path checks, exact dependency provenance, and
  Forgejo/GitHub library ref parity passed on the development host.

### 2026-09-13 14:58 CDT — Pin licensed GOTTH identity-library mains

Commit: current commit; hash assigned by Git after commit

Affected files:

- `go.mod` and `go.sum`
- identity-library release workflow record and evidence
- `workflow.events.jsonl` and `docs/CHANGELOG.md`

Explanation:

Updated the unfinished GOTTH Mail development line to the exact MIT-admitted
`gotth-oidc` and `gotth-scim` main revisions. The public module pins now
resolve to the same commits independently verified on canonical Forgejo and
public GitHub. No runtime API changed; the dependency content adds only the
admitted license and its library workflow evidence.

This does not claim that the consumer adapters exist or that either library is
ready for an immutable tag. Protected OIDC attempt/session persistence,
transactional SCIM persistence and product projection, opaque resource-ID
migration, and live Authentik lifecycle proof remain blocking work. Nothing
was tagged, released, merged to product `main`, or deployed.

Verification:

- focused consumer contract tests passed;
- full and race test suites, vet, and all command builds passed on the
  development host;
- exact module-version assertions and Forgejo/GitHub main-ref assertions were
  run separately and passed; and
- the generic repository manifest/path audit failed on the pre-existing
  missing source path `proto/gotth/mail/notification/v1`; this pin-only change
  does not repair or conceal that unrelated repository defect.

### 2026-09-13 15:08 CDT — Define the 1.0 release line and pin GOTTH identity libraries

Commit: current commit; hash assigned by Git after commit

Affected files:

- `README.md`, `go.mod`, and `go.sum`
- release-line PRD, architecture, and implementation specification
- product PRD, architecture index, and implementation index
- `internal/version` and `cmd/gotth-mailctl`
- GOTTH OIDC/SCIM external-consumer contract tests
- `workflow.toml`, `workflow/COVERAGE.md`, and release-line workflow records
- `docs/CHANGELOG.md`

Explanation:

Replaced the misleading product-version interpretation of the historical
`v0` through `v5` workflow IDs. They remain immutable capability identifiers
inside one product release line. Incomplete builds are now constrained to
`1.0.0-alpha.N`, feature-complete acceptance builds to `1.0.0-beta.N`, and the
first stable tag to exactly `1.0.0`. The binary version grammar and tag mapping
are executable, and `gotth-mailctl version` exposes the linked build identity.

Pinned the public `gotth-oidc` and `gotth-scim` modules to exact reviewed
pseudo-versions and raised the Go directive to their documented Go 1.26.6
runtime. External-consumer tests prove real OIDC discovery/PKCE authorization
start and SCIM User create/read behavior. This proves the libraries fit GOTTH
Mail; it does not lie about the unfinished application adapters. The contract
records the remaining protected-attempt/session persistence, transactional
SCIM store/password/audit projection, opaque resource-ID migration, and live
Authentik cutover work.

Verification:

- `git diff --check` passed;
- focused version, identity-module contract, and CLI tests passed;
- final full, race, vet, build, manifest, and remote-ref verification will be
  recorded in workflow evidence before the feature is marked done.

### 2026-09-13 14:02 CDT — Record GOTTH Mail canonical admission boundary

Commit: current commit; hash assigned by Git after commit

Affected files:

- project-identity PRD, architecture, implementation, workflow, and evidence
  records
- `workflow.events.jsonl`
- `docs/CHANGELOG.md`

Explanation:

Recorded the real post-operation boundary on the unfinished development line.
Forgejo repository ID 46 is now the private canonical
`gotthboard/gotth-mail` repository. The renamed v2-v5 implementation remains
separate from `main`, and its previously recovered work is preserved.

Full GOTTH-series admission remains blocked: the matching public GitHub
repository does not exist or is inaccessible, neither execution host has an
authenticated GitHub session, and Forgejo has no push mirror configured. The
identity feature is marked `blocked`; no fake mirror or credential was invented.

Verification:

- full tests, race tests, vet, renamed command builds, shell syntax, Compose
  rendering, protobuf regeneration, diff check, and current-name audit passed
  on the renamed development implementation parent
  `26b20599fac8a8ca612259d2ea00d327777878b1`;
- admitted `main` and both Forgejo PRs were verified at
  `fb1fcb893bf47aa00014c1a55b156603d463eb9a`;
- Forgejo API identity, permissions, old-path behavior, SSH refs, GitHub
  destination status, and empty push-mirror state were read independently.

### 2026-09-13 13:44 CDT — Correct renamed exact-sender header tokens

Commit: current commit; hash assigned by Git after commit

Affected files:

- `internal/webmail/openpgp.go`
- `internal/webmail/openpgp_test.go`
- `internal/webmail/webmail_test.go`
- `internal/api/api_test.go`
- `docs/CHANGELOG.md`

Explanation:

The first rename pass incorrectly rendered the exact-sender extension header
prefix as `X-GOTTH Mail-`, which contains a space and is not a valid RFC field
name. The full development-host suite caught the damage in the duplicate
signed-header rejection test. The canonical machine prefix is
`X-GOTTH-Mail-`; the signer, verifier, fixtures, and adversarial tests now use
that token consistently. No mail or external notification was sent.

Verification:

- `git diff --check` passed;
- `go test -p=1 ./internal/webmail ./internal/api` passed with
  `GOMAXPROCS=2`;
- the failed duplicate-header regression now rejects the renamed extension
  header rather than accepting it through invalid-header parsing.

### 2026-09-13 13:39 CDT — Rename the project to GOTTH Mail

Commit: current commit; hash assigned by Git after commit

Affected files:

- `README.md`, `LICENSE`, `go.mod`, and `Dockerfile`
- `cmd/gotth-mail`, `cmd/gotth-mailctl`, and `cmd/gotth-mail-plugin`
- `internal/**`, `compose/reference/**`, `scripts/**`, and `test/**`
- `proto/gotth/mail/plugin/v1/**`
- current PRD, architecture, implementation, and reference documents under
  `docs/`
- `workflow.toml`, `workflow/COVERAGE.md`, and
  `workflow/features/project.identity/**`
- `docs/CHANGELOG.md`

Explanation:

Renamed the former pre-production GopherMailForge identity to **GOTTH Mail**
and defined it as part of the canonical GOTTH project series. The canonical
repository contract is now private Forgejo development at
`gotthboard/gotth-mail` with one-way public GitHub distribution at the same
owner/slug. The Go module is `forgejo/gotthboard/gotth-mail`; the daemon, CLI,
and plugin runner are `gotth-mail`, `gotth-mailctl`, and `gotth-mail-plugin`.
First-party environment variables, OIDC/group fixtures, cookies, plugin
metadata, configuration fragments, Compose service names, database fixtures,
temporary artifact names, OpenPGP identity labels, protobuf source/package
names, imports, scripts, tests, and current documentation now use that
identity.

This is a pre-production breaking rename, not a compatibility abstraction.
There is no admitted production GOTTH Mail deployment to protect with a
permanent duplicate naming surface. Development OIDC/SCIM objects and browser
sessions must be reconciled before the next live identity proof. Historical
commits, tags, old changelog entries, dated evidence, and append-only workflow
events remain untouched and therefore continue to describe what actually ran
under the former name. Unfinished v2-v5 functionality remains unfinished; the
rename does not manufacture release readiness.

Verification completed before this checkpoint:

- `git diff --check` passed;
- every repository shell script passed `sh -n`;
- `go test -p=1 ./cmd/... ./test/contract/...` passed with
  `GOMAXPROCS=2` on the agent host;
- all three renamed commands built successfully;
- protobuf Go and gRPC bindings were regenerated with
  `protoc-gen-go v1.36.11` and `protoc-gen-go-grpc v1.6.2`;
- the current-name audit found no former-name identifier in current source,
  tests, configuration, current specifications, workflow state, or current
  workflow README files. Remaining former-name occurrences are confined to
  immutable Git metadata or declared historical changelog/evidence/event
  records.

Full development-host tests, remote admission, Forgejo repository
rename/transfer, redirect verification, and GitHub distribution status are
recorded separately when completed.

### 2026-07-19 06:55 CDT — Add configured system-identity signed-email notification slice

Commit: current commit; hash assigned by Git after commit

Affected files:

- `internal/notifyruntime/email_backend.go`
- `internal/notifyruntime/email_backend_test.go`
- `internal/notifyruntime/email_config.go`
- `internal/notifyruntime/email_config_test.go`
- `cmd/gmf-plugin/main.go`
- `cmd/gmf-plugin/main_test.go`
- `compose/reference/docker-compose.yml`
- `internal/plugin/first.go`
- `internal/plugin/first_test.go`
- `internal/plugin/notification.go`
- `internal/plugin/notification_test.go`
- `internal/notification/notification.go`
- `internal/notification/notification_test.go`
- `internal/notification/sql.go`
- `internal/notification/sql_test.go`
- `internal/api/api_test.go`
- `internal/store/sql.go`
- `internal/store/sql_test.go`
- `internal/store/store.go`
- `internal/store/evidence_migration_test.go`
- `internal/store/migration_parity_test.go`
- `migrations/0002_notification_delivery_evidence.sql`
- `internal/ops/v3.go`
- `internal/ops/v3_sql_test.go`
- `internal/webmail/openpgp.go`
- `internal/webmail/openpgp_test.go`
- `internal/webmail/smtp.go`
- `internal/webmail/smtp_test.go`
- `internal/webmail/webmail.go`
- `internal/webmail/webmail_test.go`
- `proto/gophermailforge/plugin/v1/plugin.proto`
- `proto/gophermailforge/plugin/v1/plugin.pb.go`
- `scripts/containerized-notification-plugin-smoke.sh`
- `test/contract/v1_plugins_contract_test.go`
- `test/contract/signed_email_plugin_contract_test.go`
- `docs/architecture/v5-notifications.md`
- `docs/implementation/v5-notifications.md`
- `workflow/COVERAGE.md`
- `workflow/README.md`
- `workflow.toml`
- `workflow.events.jsonl`
- `workflow/features/v5.notifications/README.md`
- `workflow/features/v5.notifications/telegram-plugin-alerts/README.md`
- `workflow/features/v5.notifications/commands-approvals/README.md`
- `workflow/features/v5.notifications/openpgp-signed-email/README.md`
- `workflow/features/v5.notifications/openpgp-signed-email/evidence/2026-07-19-signed-email-notification-runtime.md`
- `README.md`
- `docs/CHANGELOG.md`

Explanation:

Added a distinct opt-in standalone signed-email notification plugin adapter and wired it through explicit process configuration and an opt-in Compose profile. The adapter reloads exactly one active configured system-sender/private-key binding for each delivery, sanitizes alerts with whole-field redaction for JSON/multiword/Unicode-whitespace credential markers and real `PGP PRIVATE KEY BLOCK` armor, builds RFC 2047/quoted-printable seven-bit MIME with a stable Message-ID, signs with OpenPGP/MIME, requires one canonical headerless detached-signature armor block containing exactly one SHA-256 signature packet as advertised by `micalg=pgp-sha256`, cryptographically verifies that same hash plus the exact raw signed entity and authoritative headers, and only then submits the verified bytes through a trusted local SMTP relay. Missing/revoked/expired/ambiguous/disabled/mismatched/unusable or replaced keys, key types whose maintained signing path cannot emit SHA-256, noncanonical or multi-packet signatures, duplicate security-bearing headers, forged signatures, invalid configuration, and unsafe payloads fail closed before SMTP. Unsupported signing hashes are permanent admission failures and never call SMTP.

Alert sanitization now rejects secret markers in IDs, classes, correlation IDs, and resource types before those identifiers can be bounded. It checks the complete normalized detail key before truncation, redacts secret-marked keys deterministically even when bounded keys collide, and validates each typed delivery-evidence field before memory, SQL, or gRPC persistence. Sink-supplied gRPC descriptions and details are discarded for both alert and prompt calls and rebuilt as fixed server-owned status text; the intentional prompt-only `Unimplemented` contract retains its code with a fixed description.

A typed protobuf evidence field carries bounded exact-sender metadata over gRPC. The additive SQL migration preserves the immutable `d432e5b` baseline, validates the entire ledger before applying a missing known upgrade, and rejects missing, dirty, checksum-mismatched, or unknown/future ledger rows as well as a pre-existing wrong column shape. Migration and isolated-restore transactions pin `search_path` to `public, pg_catalog`; hostile caller search paths cannot redirect DDL, restored data, or readback into a shadow schema. Fresh and upgraded databases use the same registered migration definition/checksum, and isolated restore still requires `public` to contain no user relations. SMTP rejection, pre-acceptance outage, and ambiguous DATA acceptance have distinct retry semantics; successful DATA is not retried because QUIT failed. The notification smoke uses noninteractive sudo fallback and a unique Compose project so unattended verification cannot stall on a password prompt or tear down another run. The control-plane alert dispatcher still uses the default registry and does not select this adapter or compose its result with the SQL recorder; that is an explicit blocker, not hidden behind the child-process integration.

The Telegram default registry and behavior remain unchanged. The signed-email plugin has no prompt/mutation capability, no signing key is committed, and no external email was sent during verification. The active checkout was relocated from volatile `/tmp` storage to its manifest-recorded durable v5 worktree. The feature remains `in_progress` because the v5 root prerequisite, manifest dependencies, control-plane routing/selection and recorder composition, per-user/role/delegation identity selection, public-key discovery, full lifecycle policy, and production key custody are unresolved.

Workflow state was reconciled rather than hidden: the v5 root and signed-email slice moved to `in_progress` for this active work, the commands/approvals feature moved from stale `planned` to `in_progress` because its existing read-only-command, approval-binding, and narrow mutation seams are implemented but unfinished, and the Telegram README now matches its already-`in_progress` manifest state. None of these features is represented as `done`.

Verification:

- repeated focused/adversarial package tests passed for `cmd/gmf-plugin`, `internal/notification`, `internal/plugin`, `internal/notifyruntime`, `internal/ops`, `internal/store`, and `internal/webmail`, including canonical armor/single-packet admission, unsupported-key permanent classification, raw-entity/header mutation, lifecycle transitions, pre-bound secret rejection, typed evidence filtering, fixed-text alert/prompt gRPC failures, complete migration lineage, hostile search paths, wrong schema shape, and isolated-restore rejection;
- `go test -race -count=1 ./cmd/gmf-plugin ./internal/api ./internal/notification ./internal/plugin ./internal/notifyruntime ./internal/store ./internal/ops ./internal/webmail` passed;
- `go test -count=1 ./...` passed;
- `go vet ./...`, `git diff --check -- .`, and `sh -n` for every repository shell script passed;
- pinned protobuf regeneration matched the checked-in Go bindings byte-for-byte;
- the old-schema PostgreSQL migration, idempotent rerun, baseline dirty/checksum rejection, wrong-column-shape rejection, fresh/upgraded ledger equivalence, file/runtime SQL parity, and empty-only isolated-restore regressions passed;
- the `signed-email-notification` Compose profile rendered the dedicated internal plugin service;
- `scripts/containerized-notification-plugin-smoke.sh` completed under project `gmf-notification-plugin-smoke-final-20260719-6` with exit `0`, printed `containerized notification plugin gRPC/backend smoke passed`, named the real-process gRPC-to-SMTP exact-sender integration test as passed, and left zero project containers, networks, or volumes;
- `scripts/containerized-webmail-smtp-smoke.sh` completed under project `gmf-webmail-smtp-smoke-final-20260719-3` with exit `0`, printed `containerized webmail SMTP smoke passed`, exercised the shared SMTP/OpenPGP path, and left zero project containers, networks, or volumes.

### 2026-07-18 CDT — Add narrow approved notification mutation executor

Commit: `d432e5b`

Affected files:

- `internal/notifyruntime/executor.go`
- `internal/notifyruntime/executor_test.go`
- `scripts/containerized-notification-plugin-smoke.sh`
- `test/contract/v1_plugins_contract_test.go`
- `docs/implementation/v5-notifications.md`
- `workflow/COVERAGE.md`
- `workflow/features/v5.notifications/commands-approvals/evidence/2026-07-18-approved-mutation-executor.md`
- `README.md`
- `docs/CHANGELOG.md`

Explanation:

Added `notifyruntime.ApprovalExecutor`, which confirms durable SQL approval bindings and then executes only the admitted queue mutation set (`queue:flush`, `queue:retry`) through existing ops methods. Unsupported approved actions fail closed and are audited. This deliberately avoids a generic chat-to-shell or arbitrary mutation registry.

Verification:

- `go test -count=1 ./internal/notifyruntime` passed.
- `scripts/containerized-notification-plugin-smoke.sh` now runs executor tests inside `test-runner`.

### 2026-07-18 CDT — Add Telegram update receiver core

Commit: `d432e5b`

Affected files:

- `internal/notification/telegram.go`
- `internal/notification/telegram_test.go`
- `scripts/containerized-notification-plugin-smoke.sh`
- `test/contract/v1_plugins_contract_test.go`
- `docs/implementation/v5-notifications.md`
- `workflow/COVERAGE.md`
- `workflow/features/v5.notifications/commands-approvals/evidence/2026-07-18-telegram-update-receiver-core.md`
- `README.md`
- `docs/CHANGELOG.md`

Explanation:

Added a Telegram-shaped update receiver core for bounded read-only commands and approval callbacks. Commands route through explicit actor mapping and `CommandService`; approval callbacks route through durable SQL approval binding checks. The receiver does not call Telegram APIs and does not execute approved mutations.

Verification:

- `go test -count=1 ./internal/notification` passed.
- `scripts/containerized-notification-plugin-smoke.sh` now runs receiver tests inside `test-runner`.

### 2026-07-18 CDT — Add runtime notification command summaries

Commit: `d432e5b`

Affected files:

- `internal/notifyruntime/provider.go`
- `internal/notifyruntime/provider_test.go`
- `scripts/containerized-notification-plugin-smoke.sh`
- `test/contract/v1_plugins_contract_test.go`
- `docs/implementation/v5-notifications.md`
- `workflow/COVERAGE.md`
- `workflow/features/v5.notifications/commands-approvals/evidence/2026-07-18-runtime-command-provider.md`
- `README.md`
- `docs/CHANGELOG.md`

Explanation:

Added a runtime command provider for v5 read-only notification commands. It summarizes existing doctor, queue, domain, backup, deployment, and plugin state without shell execution, broad logs, Docker calls, database handles, or mutation authority.

Verification:

- `go test -count=1 ./internal/notification ./internal/notifyruntime` passed.
- `scripts/containerized-notification-plugin-smoke.sh` now runs the provider tests in `test-runner`.

### 2026-07-18 CDT — Add real OpenPGP/MIME exact-sender signing

Commit: `d432e5b`

Affected files:

- `go.mod`
- `go.sum`
- `internal/webmail/openpgp.go`
- `internal/webmail/openpgp_test.go`
- `internal/webmail/webmail.go`
- `internal/webmail/webmail_test.go`
- `scripts/containerized-webmail-smtp-smoke.sh`
- `test/contract/v1_plugins_contract_test.go`
- `docs/implementation/v4-webmail.md`
- `workflow/COVERAGE.md`
- `workflow/features/v4.webmail/production-webmail/evidence/2026-07-18-openpgp-mime-exact-sender.md`
- `README.md`
- `docs/CHANGELOG.md`

Explanation:

Added real OpenPGP/MIME `multipart/signed` signing and exact-sender verification using the maintained ProtonMail OpenPGP fork. The verifier parses the signed MIME structure, verifies the detached signature, and checks visible From plus signed sender-binding assertions against the expected fingerprint. The old loose string-grep validator was replaced with parser-backed structure validation.

Verification:

- `go test -count=1 ./internal/webmail` passed.
- `scripts/containerized-webmail-smtp-smoke.sh` now includes real OpenPGP/MIME signer/verifier tests inside the repo-owned `test-runner` container.

### 2026-07-18 CDT — Add containerized custom webmail UI shell smoke

Commit: `d432e5b`

Affected files:

- `internal/api/webmail.go`
- `internal/api/api_test.go`
- `scripts/containerized-webmail-ui-smoke.sh`
- `test/contract/v1_plugins_contract_test.go`
- `docs/implementation/v4-webmail.md`
- `workflow/COVERAGE.md`
- `workflow/features/v4.webmail/production-webmail/evidence/2026-07-18-containerized-custom-webmail-ui-smoke.md`
- `README.md`
- `docs/CHANGELOG.md`

Explanation:

Added a minimal GopherMailForge-owned `/webmail` shell and a repo-owned Compose smoke that proves it is reachable from the `test-runner` container. This closes custom webmail UI/container reachability without pretending Roundcube is the custom UI.

Verification:

- `go test -count=1 ./internal/api` passed.

### 2026-07-18 CDT — Add notification backend gRPC seam

Commit: `d432e5b`

Affected files:

- `proto/gophermailforge/plugin/v1/plugin.proto`
- `proto/gophermailforge/plugin/v1/plugin.pb.go`
- `proto/gophermailforge/plugin/v1/plugin_grpc.pb.go`
- `internal/plugin/notification.go`
- `internal/plugin/notification_test.go`
- `internal/plugin/grpc_test.go`
- `internal/plugin/first.go`
- `cmd/gmf-plugin/main.go`
- `scripts/containerized-notification-plugin-smoke.sh`
- `docs/implementation/v5-notifications.md`
- `workflow/COVERAGE.md`
- `workflow/features/v5.notifications/telegram-plugin-alerts/evidence/2026-07-18-notification-backend-grpc-smoke.md`
- `README.md`
- `docs/CHANGELOG.md`

Explanation:

Added the notification-specific protobuf/gRPC backend seam for `SendAlert` and `SendPrompt`, registered it in the repo-owned notification plugin container, and extended the container smoke to exercise both plugin-control and notification-backend RPCs. The prompt RPC delivers prompt payloads only; it does not approve, execute mutations, or grant Telegram state authority.

Verification:

- `go test -count=1 ./internal/plugin ./cmd/gmf-plugin ./proto/gophermailforge/plugin/v1` passed.

### 2026-07-18 CDT — Add notification read-only command core

Commit: `d432e5b`

Affected files:

- `internal/notification/commands.go`
- `internal/notification/commands_test.go`
- `docs/implementation/v5-notifications.md`
- `workflow/COVERAGE.md`
- `workflow/features/v5.notifications/commands-approvals/evidence/2026-07-18-readonly-command-core.md`
- `README.md`
- `docs/CHANGELOG.md`

Explanation:

Added a local notification read-only command dispatcher that maps transport actors explicitly, authorizes command-specific read actions, calls only a bounded summary provider, redacts/bounds returned text, and audits denied, failed, and successful attempts. It intentionally exposes no shell, mutation callback, database handle, or Telegram send primitive.

Verification:

- `go test -count=1 ./internal/notification` passed.

### 2026-07-18 CDT — Add SQL notification actor mapping and approval binding

Commit: `d432e5b`

Affected files:

- `internal/notification/approval.go`
- `internal/notification/approval_test.go`
- `internal/store/store.go`
- `migrations/0001_initial.sql`
- `docs/implementation/v5-notifications.md`
- `workflow/COVERAGE.md`
- `workflow/features/v5.notifications/commands-approvals/evidence/2026-07-18-actor-mapping-approval-binding.md`
- `workflow/features/v5.notifications/telegram-plugin-alerts/evidence/2026-07-18-local-alert-core.md`
- `README.md`
- `docs/CHANGELOG.md`

Explanation:

Added configured SQL actor mapping and approval prompt binding primitives for v5 notifications. Transport actors must map explicitly to `authz.Actor`; chat membership alone grants nothing. Approval confirmation now has durable single-use binding checks for transport actor, mapped actor, action, resource, request hash, and expiry. This intentionally stops before Telegram live delivery, read-only command service plumbing, or mutation execution.

Verification:

- `go test -count=1 ./internal/notification ./internal/store` passed.

### 2026-07-18 CDT — Expose SQL notification delivery status

Commit: `d432e5b`

Affected files:

- `internal/notification/sql.go`
- `internal/notification/sql_test.go`
- `internal/api/api.go`
- `internal/api/api_test.go`
- `internal/store/store.go`
- `migrations/0001_initial.sql`
- `docs/implementation/v5-notifications.md`
- `workflow/COVERAGE.md`
- `workflow/features/v5.notifications/telegram-plugin-alerts/evidence/2026-07-18-local-alert-core.md`
- `workflow/features/v5.notifications/telegram-plugin-alerts/evidence/2026-07-18-sql-delivery-status-api.md`
- `README.md`
- `docs/CHANGELOG.md`

Explanation:

Added SQL-backed notification delivery records and a read-only authorized API surface for operator visibility. This closes the configured runtime/API delivery-status surface without adding Telegram live delivery, prompt mutation authority, or approval workflows.

Verification:

- `go test -count=1 ./internal/notification ./internal/api ./internal/store` passed.

### 2026-07-18 CDT — Add bounded raw MIME parser and text-only rendering decision

Commit: `d432e5b`

Affected files:

- `internal/webmail/mime.go`
- `internal/webmail/mime_test.go`
- `internal/webmail/imap.go`
- `test/fixtures/webmail/hostile-multipart.eml`
- `test/fixtures/webmail/mime-part-flood.eml`
- `docs/implementation/v4-webmail.md`
- `workflow/COVERAGE.md`
- `workflow/features/v4.webmail/production-webmail/evidence/2026-07-18-full-finish-blockers.md`
- `workflow/features/v4.webmail/production-webmail/evidence/2026-07-18-raw-mime-text-rendering.md`
- `README.md`
- `docs/CHANGELOG.md`

Explanation:

Added bounded raw MIME parsing for IMAP-fetched messages with hostile fixture coverage. The parser walks multipart MIME with nesting/part limits, decodes base64 and quoted-printable parts, extracts text/html-as-data/attachments, sanitizes attachment boundaries, and fails closed on malformed multipart boundaries. v4 now explicitly uses conservative text-only HTML rendering instead of pretending regex-based rich sanitization is a production security boundary.

Verification:

- `go test -count=1 ./internal/webmail` passed.

### 2026-07-18 CDT — Persist SQL webmail draft metadata

Commit: `d432e5b`

Affected files:

- `internal/webmail/webmail.go`
- `internal/webmail/sql_draft_store_test.go`
- `internal/api/api_test.go`
- `internal/store/store.go`
- `migrations/0001_initial.sql`
- `docs/implementation/v4-webmail.md`
- `workflow/COVERAGE.md`
- `workflow/features/v4.webmail/production-webmail/evidence/2026-07-18-durable-draft-store.md`
- `workflow/features/v4.webmail/production-webmail/evidence/2026-07-18-full-finish-blockers.md`
- `workflow/features/v4.webmail/production-webmail/evidence/2026-07-18-sql-draft-metadata-durability.md`
- `README.md`
- `docs/CHANGELOG.md`

Explanation:

Extended the configured SQL draft path so reply/forward source IDs and attachment metadata/content survive process reload. The mailbox ownership guard remains on conflict updates; API draft creation still ignores caller-supplied IDs and binds the draft to the authenticated mailbox.

Verification:

- `go test -count=1 ./internal/webmail ./internal/api ./internal/store` passed.

### 2026-07-18 CDT — Add containerized webmail IMAP smoke

Commit: `d432e5b`

Affected files:

- `internal/webmail/imap.go`
- `internal/webmail/imap_test.go`
- `scripts/containerized-webmail-imap-smoke.sh`
- `scripts/containerized-mailu-import-smoke.sh`
- `scripts/containerized-webmail-smtp-smoke.sh`
- `scripts/containerized-notification-plugin-smoke.sh`
- `test/contract/v1_plugins_contract_test.go`
- `docs/implementation/v4-webmail.md`
- `workflow/COVERAGE.md`
- `workflow/features/v4.webmail/production-webmail/evidence/2026-07-18-full-finish-blockers.md`
- `workflow/features/v4.webmail/production-webmail/evidence/2026-07-18-containerized-webmail-imap-smoke.md`
- `README.md`
- `docs/CHANGELOG.md`

Explanation:

Added a small real `webmail.NetIMAPClient` transport adapter for Dovecot-backed folder/list/search/read operations and a repo-owned containerized smoke that injects a message through the real SMTP adapter, then reads it back through Dovecot IMAP from the Compose `test-runner`. The smoke exposed two real issues and they were fixed: Dovecot namespace delimiter noise from `LIST` must not be shown as a mailbox, and container smoke scripts must rebuild the `test-runner` image before running tests or cached images can lie.

Verification:

- `go test -count=1 ./internal/webmail ./test/contract` passed.
- `scripts/containerized-webmail-imap-smoke.sh` passed, including container build-stage `go test ./...`, SMTP injection through Compose Postfix, and live IMAP read from `dovecot:143`.

### 2026-07-18 CDT — Add containerized notification plugin gRPC smoke

Commit: `d432e5b`

Affected files:

- `compose/reference/docker-compose.yml`
- `internal/plugin/first.go`
- `internal/plugin/first_test.go`
- `internal/plugin/grpc_test.go`
- `scripts/containerized-notification-plugin-smoke.sh`
- `test/contract/v1_plugins_contract_test.go`
- `docs/implementation/v5-notifications.md`
- `workflow/COVERAGE.md`
- `workflow/features/v5.notifications/telegram-plugin-alerts/evidence/2026-07-18-local-alert-core.md`
- `workflow/features/v5.notifications/telegram-plugin-alerts/evidence/2026-07-18-containerized-notification-plugin-grpc-smoke.md`
- `README.md`
- `docs/CHANGELOG.md`

Explanation:

Added `telegram-notification-sink` as a notification first-mechanism plugin, wired a `notification-plugin` service into the repo-owned reference Compose topology, and added an env-gated live gRPC plugin-control smoke. The smoke starts the containerized plugin, runs authenticated health/version/capability checks from the Compose `test-runner`, and verifies wrong-token rejection. This is intentionally only the plugin container/control seam; the notification-specific SendAlert/prompt protobuf service and live Telegram API delivery remain blockers.

Verification:

- `go test -count=1 ./internal/plugin ./test/contract` passed.
- `git diff --check -- .` passed.
- `scripts/containerized-notification-plugin-smoke.sh` passed, including container build-stage `go test ./...`, live gRPC control checks against `notification-plugin:9443`, and wrong-token rejection.

### 2026-07-18 CDT — Add containerized webmail SMTP transport smoke

Commit: `d432e5b`

Affected files:

- `internal/webmail/smtp.go`
- `internal/webmail/smtp_test.go`
- `scripts/containerized-webmail-smtp-smoke.sh`
- `test/contract/v1_plugins_contract_test.go`
- `docs/implementation/v4-webmail.md`
- `workflow/COVERAGE.md`
- `workflow/features/v4.webmail/production-webmail/evidence/2026-07-18-full-finish-blockers.md`
- `workflow/features/v4.webmail/production-webmail/evidence/2026-07-18-containerized-webmail-smtp-smoke.md`
- `README.md`
- `docs/CHANGELOG.md`

Explanation:

Added a real `webmail.NetSMTPSubmitter` transport adapter for already-built/already-signed MIME bytes and a repo-owned containerized smoke that runs the adapter test inside the Compose `test-runner` container against the reference Postfix service, then verifies delivery into the smoke Maildir. This closes the fake-only SMTP transport gap without claiming full webmail send completion; OpenPGP/MIME exact-sender signing remains required before production webmail send can be admitted.

Verification:

- `go test -count=1 ./internal/webmail ./test/contract` passed.
- `git diff --check -- .` passed.
- `scripts/containerized-webmail-smtp-smoke.sh` passed, including container build-stage `go test ./...`, live SMTP submitter test against `postfix:25`, and Maildir delivery verification.

### 2026-07-18 CDT — Add containerized Mailu import smoke fixture

Commit: `d432e5b`

Affected files:

- `compose/reference/docker-compose.yml`
- `scripts/containerized-mailu-import-smoke.sh`
- `test/contract/v1_plugins_contract_test.go`
- `workflow/COVERAGE.md`
- `workflow/features/v3.ops-import-admin/production-ops/evidence/2026-07-18-full-finish-blockers.md`
- `workflow/features/v3.ops-import-admin/production-ops/evidence/2026-07-18-containerized-mailu-import-smoke.md`
- `README.md`
- `docs/CHANGELOG.md`

Explanation:

Moved the Mailu import compatibility fixture into the repo-owned reference Compose topology. Added a `test-runner` service using the Dockerfile build target and a `mailu-import` profile with Mailu admin plus Redis, isolated volumes, no public mail ports, and dev-only fixture configuration. Added `scripts/containerized-mailu-import-smoke.sh` to start the fixture, seed representative Mailu state, export redacted and secret config into a temporary directory, validate the live Mailu export shape, and run focused import/API tests inside the Compose test-runner container. Added contract tests so the Compose fixture and smoke script cannot silently disappear or start overwriting checked-in fixtures again.

Verification:

- `sudo docker compose -f compose/reference/docker-compose.yml --profile mailu-import --profile test config` passed.
- `go test -count=1 ./test/contract ./internal/ops ./internal/api` passed.
- `git diff --check -- .` passed.
- `go test -count=1 ./...` passed.
- `scripts/containerized-mailu-import-smoke.sh` passed, including container build-stage `go test ./...`, containerized focused import/API tests, and live Mailu export shape checks.

### 2026-07-18 CDT — Add durable webmail drafts and local notification core

Commit: 1da110a

Affected files:

- `internal/webmail/webmail.go`
- `internal/webmail/sql_draft_store_test.go`
- `internal/api/webmail.go`
- `internal/api/api_test.go`
- `internal/notification/notification.go`
- `internal/notification/notification_test.go`
- `workflow.toml`
- `workflow.events.jsonl`
- `workflow/COVERAGE.md`
- `workflow/features/v4.webmail/production-webmail/evidence/2026-07-18-full-finish-blockers.md`
- `workflow/features/v4.webmail/production-webmail/evidence/2026-07-18-durable-draft-store.md`
- `workflow/features/v5.notifications/telegram-plugin-alerts/evidence/2026-07-18-local-alert-core.md`
- `README.md`
- `docs/CHANGELOG.md`

Explanation:

Added durable mailbox-owned webmail draft persistence behind a narrow `webmail.DraftStore` seam. The default memory behavior remains for unconfigured callers, while `webmail.SQLDraftStore` uses the existing `webmail_drafts` table for configured SQL deployments. Webmail submit now persists state transitions through the configured store, and API wiring uses SQL draft persistence when `api.Server.AuditDB` is configured. This closes the local durable-draft slice without pretending production IMAP, SMTP, OpenPGP/MIME, raw MIME parsing, rich sanitizer/browser proof, attachment metadata durability, or UI/container reachability are done.

Added a local `internal/notification` alert core for v5. It defines a bounded sanitized alert contract, redacts secret-looking values before backend delivery, records pending/final delivery state, exposes retryable failure status, and only passes a sanitized `Alert` to the injected backend. This is fake-backend local groundwork only; it does not claim Telegram plugin/container/gRPC delivery, live Telegram sends, approval binding, or OpenPGP-signed email notifications are complete.

Verification:

- Confirmed `go test -count=1 ./internal/notification ./internal/webmail ./internal/api ./internal/store` passes.
- Full repository verification is run before commit.

### 2026-07-18 CDT — Record v3 configured-path completion under v2 blocker

Commit: 9d634be

Affected files:

- `workflow.toml`
- `workflow.events.jsonl`
- `workflow/features/v3.ops-import-admin/production-ops/evidence/2026-07-18-full-finish-blockers.md`
- `README.md`
- `docs/CHANGELOG.md`

Explanation:

Updated canonical workflow state for v3 configured-path child slices after the SQL audit/retention, isolated SQL restore, verified-backup snapshot linkage, canonical SQL bulk mutation, and live Mailu config-export import repairs passed verification. The v3 child features and production-ops finishing child are now marked done in `workflow.toml`, while the v3 root itself remains `in_progress` because the root dependency chain still passes through the v2 live Authentik browser/passkey/group-claim blocker. Cleaned stale evidence language from earlier incremental slices so old blocker notes are clearly historical and superseded rather than current truth.

Verification:

- Workflow state was inspected directly from `workflow.toml`.
- Full repository verification is run before commit.

### 2026-07-18 CDT — Import live Mailu config-export password state

Commit: dc409f6

Affected files:

- `internal/ops/v3.go`
- `internal/ops/v3_test.go`
- `internal/ops/v3_sql_test.go`
- `internal/api/v3.go`
- `internal/api/api_test.go`
- `test/fixtures/mailu/config-export.json`
- `test/fixtures/mailu/config-export-secrets.json`
- `docs/reference/authentik-password-hashing.md`
- `docs/implementation/v3-ops-import-admin.md`
- `workflow/COVERAGE.md`
- `workflow/features/v3.ops-import-admin/production-ops/evidence/2026-07-18-full-finish-blockers.md`
- `workflow/features/v3.ops-import-admin/production-ops/evidence/2026-07-18-mailu-live-import-passwords.md`
- `README.md`
- `docs/CHANGELOG.md`

Explanation:

Added live Mailu `config-export --json` import parsing instead of relying only on synthetic candidate arrays. The importer now reads Mailu's top-level `domain`, `user`, `alias`, and `relay` export shape, preserves multi-destination aliases, rejects redacted non-secret password exports for user password preservation, and wraps Mailu Passlib `bcrypt-sha256` hashes from `config-export --secrets --json` as `mailu_bcrypt_sha256$<original-mailu-passlib-hash>`. Added SQL import apply for configured deployments so admissible Mailu imports write canonical `domains`, `mailboxes`, `aliases`, and `relays`, reload daemon state from SQL, verify imported recipients from persisted state, and write durable SQL audit through the API route. This records Bryce's proven Authentik migration mechanism without pretending Mailu hashes can be losslessly converted to Django `bcrypt_sha256` or locally verified by the existing PBKDF2-only Dovecot verifier.

Verification:

- Confirmed `go test -count=1 ./internal/ops` passes with live Mailu export fixture coverage.
- Confirmed `go test -count=1 ./internal/ops ./internal/api` passes with canonical SQL import apply and API route coverage.
- Full repository verification is run before commit.

### 2026-07-18 CDT — Apply bulk operations to canonical SQL state

Commit: 0b2eef4

Affected files:

- `internal/ops/v3.go`
- `internal/ops/v3_sql_test.go`
- `internal/api/v3.go`
- `internal/api/api_test.go`
- `workflow/COVERAGE.md`
- `workflow/features/v3.ops-import-admin/production-ops/evidence/2026-07-18-full-finish-blockers.md`
- `README.md`
- `docs/CHANGELOG.md`

Explanation:

Added canonical SQL-backed bulk mutation for configured v3 deployments. Bulk apply still requires preview binding, actor match, operation match, preview ID confirmation, preview hash, expiry, and non-empty item scope, but SQL-configured routes now mutate canonical `mailboxes` and `aliases` rows instead of only memory maps. `disable-users` and `enable-users` update mailbox enabled state, `delete-aliases` deletes alias rows, and durable audit events are written through the SQL audit writer. README and coverage records were narrowed so durable canonical bulk mutations are no longer listed as an open v3 blocker.

Verification:

- Confirmed `go test -count=1 ./internal/ops` passes with canonical SQL bulk mutation and durable audit coverage.
- Confirmed `go test -count=1 ./internal/api` passes with SQL-backed bulk API mutation coverage.
- Full repository verification is run before commit.

### 2026-07-18 CDT — Persist snapshot linkage to verified backups

Commit: 2c4050b

Affected files:

- `internal/ops/v3.go`
- `internal/ops/v3_sql_test.go`
- `internal/api/v3.go`
- `internal/api/api_test.go`
- `workflow/COVERAGE.md`
- `workflow/features/v3.ops-import-admin/production-ops/evidence/2026-07-18-full-finish-blockers.md`
- `README.md`
- `docs/CHANGELOG.md`

Explanation:

Added persisted SQL snapshot linkage for configured v3 deployments. `ops.SQLSnapshotStore` can capture, list, and retrieve snapshots from the canonical `snapshots` table, link snapshots to `backup_verifications`, and derive verified restore status from the linked backup verification row. The v3 snapshot API now reads persisted SQL snapshots when a DB is configured for list, detail/rollback guidance, and diff routes. README and coverage records were narrowed so persisted snapshot linkage is no longer listed as an open v3 blocker.

Verification:

- Confirmed `go test -count=1 ./internal/ops` passes with persisted snapshot/verified-backup linkage coverage.
- Confirmed `go test -count=1 ./internal/api` passes with SQL-backed snapshot API coverage.
- Full repository verification is run before commit.

### 2026-07-18 CDT — Add isolated SQL backup restore verification engine

Commit: 6caa51d

Affected files:

- `internal/ops/v3.go`
- `internal/ops/v3_sql_test.go`
- `internal/api/v3.go`
- `internal/api/api_test.go`
- `workflow/COVERAGE.md`
- `workflow/features/v3.ops-import-admin/production-ops/evidence/2026-07-18-full-finish-blockers.md`
- `README.md`
- `docs/CHANGELOG.md`

Explanation:

Added a real isolated SQL restore verification mechanism for configured v3 backup verification paths. The new restore engine migrates an isolated empty SQL database, restores backup artifact domain/mailbox/alias state into canonical tables, reloads daemon contract state from SQL, and runs daemon recipient contract verification against that restored state instead of only checking an in-process model. SQL backup verification recording now preserves the restore-engine reference, and the v3 API uses the configured runtime restore engine when SQL verification is enabled. The README and coverage map were narrowed so they no longer claim isolated SQL restore is still entirely absent, while preserving the remaining v3 blockers: live-compatible Mailu import, durable canonical bulk mutations, and persisted snapshot linkage.

Verification:

- Confirmed `go test -count=1 ./internal/ops` passes with SQL isolated restore, dirty restore DB rejection, and persisted restore-ref coverage.
- Confirmed `go test -count=1 ./internal/api` passes with API backup verification using a configured SQL isolated restore engine.
- Full repository verification is run before commit.

### 2026-07-18 CDT — Record root README implementation blockers

Commit: 12c003f

Affected files:

- `README.md`
- `docs/CHANGELOG.md`

Explanation:

Added a root README blocker section that exposes the remaining real implementation gaps instead of burying them in workflow evidence. The README now states that v2 still needs interactive browser/passkey Authentik authorization-code redemption with the runtime client secret and live `gophermailforge-admins` group-claim assertion. It also states that v3 still needs a real isolated restore engine, live-compatible Mailu import, durable canonical bulk mutations, and snapshot linkage, and explicitly rejects fake bulk SQL paperwork as a completion substitute.

Verification:

- Confirmed `git diff --check -- README.md docs/CHANGELOG.md` passes.

### 2026-07-18 CDT — Persist v3 backup verification records

Commit: 88355de

Affected files:

- `internal/ops/v3.go`
- `internal/ops/v3_sql_test.go`
- `internal/api/v3.go`
- `internal/api/api_test.go`
- `workflow/COVERAGE.md`
- `workflow/features/v3.ops-import-admin/production-ops/evidence/2026-07-18-full-finish-blockers.md`
- `docs/CHANGELOG.md`

Explanation:

Added durable SQL records for v3 backup verification. `ops.SQLBackupVerificationStore` records/upserts `backup_artifacts`, inserts `backup_verifications`, and can load the latest verification by artifact reference. The authenticated `/api/v1/backups/verify` route records SQL verification state when a DB is configured.

This fixes the disposable verification-record seam. It does not claim the remaining isolated-restore blocker is solved; the current restore verification mechanism is still the in-process contract model.

Verification:

- Confirmed `go test -count=1 ./internal/ops` passes with SQL artifact/verification persistence coverage.
- Confirmed `go test -count=1 ./internal/api` passes with API route SQL verification coverage.
- Full repository verification is run before commit.

### 2026-07-18 CDT — Add SQL-backed v3 audit query and retention

Commit: 55d41a5

Affected files:

- `internal/audit/audit.go`
- `internal/ops/v3.go`
- `internal/ops/v3_sql_test.go`
- `internal/api/api.go`
- `internal/api/v3.go`
- `internal/api/api_test.go`
- `workflow/COVERAGE.md`
- `workflow/features/v3.ops-import-admin/production-ops/evidence/2026-07-18-full-finish-blockers.md`
- `docs/CHANGELOG.md`

Explanation:

Added SQL-backed v3 audit read and retention paths. `ops.SQLAuditStore` now supports filtered audit queries, detail lookup, exact retention preview for `older-than-Nd`, and retention apply that writes the retention audit event and deletes expired rows in one transaction. The v3 audit export/detail/retention API routes use SQL audit storage when `api.Server.AuditDB` is configured and retain memory fallback for existing non-SQL tests.

This closes the previous memory-only audit read/retention seam for SQL deployments. Backup restore, Mailu import compatibility, durable bulk mutations, and persisted snapshot linkage remain open v3 work.

Verification:

- Confirmed `go test -count=1 ./internal/ops` passes with SQL audit query/get/retention coverage.
- Confirmed `go test -count=1 ./internal/api` passes with authenticated SQL audit route coverage.
- Full repository verification is run before commit.

### 2026-07-18 CDT — Record v2 interactive blocker and advance active work to v3

Commit: df4a8e3

Affected files:

- `workflow.toml`
- `workflow/features/v2.identity-provisioning/live-authentik-persistence/evidence/2026-07-18-full-finish-blockers.md`
- `workflow/features/v3.ops-import-admin/production-ops/evidence/2026-07-18-full-finish-blockers.md`
- `workflow/COVERAGE.md`
- `docs/CHANGELOG.md`

Explanation:

Recorded the remaining v2 blocker honestly: final browser/passkey authorization-code redemption and live `gophermailforge-admins` group assertion require an interactive browser session and the live Authentik client secret at runtime. The v2 production child remains `in_progress`; it is not marked done.

Advanced `active_feature` to `v3.ops-import-admin.production-ops` and changed that child to `in_progress` so local v3 repairs can continue while the v2 interactive proof waits.

Verification:

- Confirmed `git diff --check -- .` passes for the workflow/evidence update.

### 2026-07-18 CDT — Replace flaky embedded Postgres test dependency

Commit: 7c098b8

Affected files:

- `internal/testpg/testpg.go`
- `internal/store/sql_test.go`
- `internal/authn/sql_store_test.go`
- `internal/identity/sql_persistence_test.go`
- `go.mod`
- `go.sum`
- `workflow/COVERAGE.md`
- `workflow/features/v2.identity-provisioning/live-authentik-persistence/evidence/2026-07-18-full-finish-blockers.md`
- `docs/CHANGELOG.md`

Explanation:

Full repository verification exposed a test harness failure: `github.com/fergusstrange/embedded-postgres` tried to resolve unavailable packaged Postgres versions. Replaced that hidden external binary dependency with `internal/testpg`, a small local harness that starts installed `initdb`/`postgres`/`createdb`, creates a real temporary database, and applies the normal migrations. Store, authn, and identity SQL persistence tests still run against real Postgres constraints, but no longer depend on the embedded-postgres package's remote version table.

Verification:

- Confirmed `go test -count=1 ./internal/authn ./internal/identity ./internal/store` passes with the local harness.
- Confirmed `git diff --check -- .` passes.
- Confirmed `go test -count=1 ./...` passes.

### 2026-07-18 CDT — Preserve OIDC group claims for Authentik role mapping

Commit: 7c098b8

Affected files:

- `internal/authn/oidc.go`
- `internal/authn/oidc_test.go`
- `internal/authz/authz_test.go`
- `workflow/COVERAGE.md`
- `workflow/features/v2.identity-provisioning/live-authentik-persistence/evidence/2026-07-18-full-finish-blockers.md`
- `docs/CHANGELOG.md`

Explanation:

Preserved Authentik/OIDC ID-token `groups` on the validated GopherMailForge identity instead of dropping them at callback completion. Added authorization coverage for the installed Authentik group name `gophermailforge-admins`, proving a verified mapping grants `global_admin` authority.

This closes the local parser/mapping seam. The remaining proof is the interactive browser/passkey callback confirming the live Authentik token for `Dan` contains the expected group claim.

Verification:

- Confirmed `go test ./internal/authn ./internal/authz` passes with group-preservation and mapping coverage.
- Full repository verification is run before commit.

### 2026-07-18 CDT — Make password verifier compatibility contract honest

Commit: 6955079

Affected files:

- `internal/daemon/daemon.go`
- `internal/daemon/daemon_test.go`
- `internal/ops/v3.go`
- `internal/ops/ops_test.go`
- `docs/reference/authentik-password-hashing.md`
- `docs/implementation/v2-identity-provisioning.md`
- `docs/prd/PRD-v2-identity-provisioning.md`
- `docs/architecture/v2-identity-provisioning.md`
- `docs/implementation/IMPLEMENTATION.md`
- `docs/implementation/v3-ops-import-admin.md`
- `workflow/COVERAGE.md`
- `workflow/features/v2.identity-provisioning/live-authentik-persistence/evidence/2026-07-18-full-finish-blockers.md`
- `docs/CHANGELOG.md`

Explanation:

Removed the fake broad claim that GopherMailForge supports arbitrary Authentik/Django password hashers. The current v2 compatibility target is explicitly Django `pbkdf2_sha256`, matching the checked Authentik/Django default deployment. Added a central PBKDF2 verifier validator, tightened malformed verifier rejection, and made Mailu import use the same validator instead of a loose shape check.

Unsupported Django hashers such as `argon2`, `bcrypt_sha256`, `scrypt`, and `pbkdf2_sha1` are now documented and tested as unsupported until real local verification support exists.

Verification:

- Confirmed `go test -count=1 ./internal/daemon ./internal/ops` covers valid PBKDF2 use, unsupported hasher rejection, malformed verifier rejection, and import rejection.
- Full repository verification is run before commit.

### 2026-07-18 CDT — Record live runtime Authentik redirect smoke

Commit: 74354d0

Affected files:

- `workflow/COVERAGE.md`
- `workflow/features/v2.identity-provisioning/live-authentik-persistence/evidence/2026-07-18-full-finish-blockers.md`
- `docs/CHANGELOG.md`

Explanation:

Recorded live runtime evidence for the installed Authentik integration. The actual `cmd/gophermailforge` runtime was started on `127.0.0.1:18080` with the installed Authentik issuer/client ID/redirect URI supplied through environment variables. Probing `/api/v1/oidc/login?mode=redirect&redirect=/done` returned a `302` to `auth.dannyhunn.com` with the exact configured callback URI, generated state/nonce, and a browser-binding cookie.

This proves runtime startup, discovery/JWKS loading, and browser authorization redirect against the installed Authentik provider. It still does not claim final passkey browser code redemption through the callback; that remains the interactive proof.

Verification:

- Confirmed live runtime login redirect against installed Authentik.
- Confirmed `git diff --check -- .` passes.

### 2026-07-18 CDT — Wire runtime Authentik OIDC discovery from environment

Commit: 8a1c37b

Affected files:

- `cmd/gophermailforge/main.go`
- `cmd/gophermailforge/oidc_env_test.go`
- `workflow/COVERAGE.md`
- `workflow/features/v2.identity-provisioning/live-authentik-persistence/evidence/2026-07-18-full-finish-blockers.md`
- `docs/CHANGELOG.md`

Explanation:

Wired the `gophermailforge` runtime to configure OIDC from installed Authentik environment variables. When `GMF_AUTHENTIK_ISSUER`, `GMF_AUTHENTIK_CLIENT_ID`, and `GMF_AUTHENTIK_REDIRECT_URI` are supplied together, startup discovers provider metadata, validates issuer/code/RS256 support, loads JWKS, fills the API server OIDC config/authorization endpoint/JWKS, and installs an HTTP code exchanger using the supplied client secret. Partial OIDC env configuration fails closed instead of starting a half-configured login path.

This makes the installed Authentik provider usable by the runtime; the remaining proof is the interactive browser/passkey login with the real client secret supplied out-of-band.

Verification:

- Confirmed `go test ./cmd/gophermailforge` passes with an `httptest` provider proving env-driven discovery and server wiring.
- Full repository verification is run before commit.

### 2026-07-18 CDT — Add OIDC discovery and JWKS loader

Commit: 1cc7f6c

Affected files:

- `internal/authn/oidc.go`
- `internal/authn/oidc_test.go`
- `workflow/COVERAGE.md`
- `workflow/features/v2.identity-provisioning/live-authentik-persistence/evidence/2026-07-18-full-finish-blockers.md`
- `docs/CHANGELOG.md`

Explanation:

Added real OIDC provider metadata loading to the authn package. `FetchDiscovery` retrieves the issuer discovery document with bounded response size, `FetchJWKS` retrieves and validates a non-empty JWKS with bounded response size, and `DiscoverProvider` validates the discovered issuer/code/RS256 support before returning the JWKS. This removes another hand-fed fixture seam from the v2 OIDC path and gives runtime startup a real mechanism for loading installed Authentik metadata.

Verification:

- Confirmed `go test ./internal/authn` passes with an `httptest` discovery/JWKS provider.
- Full repository verification is run before commit.

### 2026-07-18 CDT — Add browser-shaped OIDC callback flow

Commit: c72dccd

Affected files:

- `internal/api/api.go`
- `internal/api/api_test.go`
- `internal/authn/oidc.go`
- `workflow/COVERAGE.md`
- `workflow/features/v2.identity-provisioning/live-authentik-persistence/evidence/2026-07-18-full-finish-blockers.md`
- `docs/CHANGELOG.md`

Explanation:

Repaired the OIDC route shape so a real browser/passkey authorization-code flow can complete through GopherMailForge. `/api/v1/oidc/login?mode=redirect` now issues a browser-binding cookie and redirects to the provider authorization endpoint. `/api/v1/oidc/callback` now accepts browser GET callbacks with query `state`/`code`, validates the binding cookie, exchanges the code through the configured exchanger, validates the ID token, sets the `gmf_session` cookie, clears the binding cookie, and redirects to the stored post-login target. The existing JSON/header callback path remains for API clients/tests.

Added an OIDC exchanger seam on `api.Server` so live runtime wiring can use the installed Authentik token endpoint/client secret without accepting caller-supplied ID tokens. Added a signed-token API regression proving redirect login, callback, session cookie, binding-cookie clearing, and redirect-after-login behavior.

Verification:

- Confirmed `go test ./internal/api` passes with browser-shaped OIDC callback coverage.
- Full repository verification is run before commit.

### 2026-07-18 CDT — Add SQL-backed identity and app-password persistence

Commit: 17f6bb3

Affected files:

- `internal/identity/identity.go`
- `internal/identity/sql_persistence_test.go`
- `internal/store/store.go`
- `internal/store/store_test.go`
- `internal/store/sql_test.go`
- `migrations/0001_initial.sql`
- `workflow.toml`
- `workflow/COVERAGE.md`
- `workflow/features/v2.identity-provisioning/live-authentik-persistence/evidence/2026-07-18-full-finish-blockers.md`
- `docs/CHANGELOG.md`

Explanation:

Continued the v2 full-finish repair by making identity state durable instead of memory-only. The identity service can now persist and reload mailboxes, mailbox password verifiers, API/SCIM token verifiers/scopes, and app-password token verifiers/revocation state through the canonical SQL schema. The schema now includes `mailboxes.verifier`, and app passwords are persisted in `tokens` with `kind='app_password'` and mailbox subject metadata. Daemon mailbox/passdb views are rebuilt from SQL-loaded state.

Added an embedded Postgres restart test proving a provisioned mailbox, mailbox password, app password, API token scopes, and app-password revocation survive fresh service construction. This closes the previous "memory-only identity/app-password state" gap for the tested service path. Runtime production DB construction and live Authentik browser/code redemption remain separate open work.

Verification:

- Confirmed `go test ./internal/identity` passes with embedded Postgres restart persistence coverage.
- Confirmed focused package gates pass before full repository verification.
- Full repository verification is run before commit.

### 2026-07-18 CDT — Add live installed Authentik OIDC smoke

Commit: 966e5ec

Affected files:

- `scripts/live-authentik-oidc-smoke.sh`
- `workflow/COVERAGE.md`
- `workflow/features/v2.identity-provisioning/live-authentik-persistence/evidence/2026-07-18-full-finish-blockers.md`
- `docs/CHANGELOG.md`

Explanation:

Configured the installed Authentik instance with a dedicated GopherMailForge OIDC application/provider (`gophermailforge`) using strict redirect URI `http://127.0.0.1:18080/api/v1/oidc/callback`, and created/used the `gophermailforge-admins` group with `Dan` as a member for live group-claim testing. Added a live smoke script that validates the installed provider discovery document, JWKS, and authorization endpoint redirect/state preservation. The live client ID is supplied at runtime and the client secret is not written into the repository.

This is real installed-provider evidence, not a local fabricated JWKS fixture. It still does not claim full browser/passkey authorization-code redemption through GopherMailForge; that requires running GMF with the live client secret and an interactive browser login.

Verification:

- Confirmed `GMF_AUTHENTIK_CLIENT_ID=<redacted> ./scripts/live-authentik-oidc-smoke.sh` passes against `https://auth.dannyhunn.com/application/o/gophermailforge/`.
- Full repository verification is run before commit.

### 2026-07-18 CDT — Add SQL-backed OIDC state and session store

Commit: 6106556

Affected files:

- `internal/authn/oidc.go`
- `internal/authn/sql_store.go`
- `internal/authn/sql_store_test.go`
- `internal/api/api.go`
- `workflow/COVERAGE.md`
- `workflow/features/v2.identity-provisioning/live-authentik-persistence/evidence/2026-07-18-full-finish-blockers.md`

Explanation:

Added a real `authn.StateStore` contract for OIDC login state and sessions, with the existing memory store and a new SQL-backed implementation. `authn.SQLStore` persists OIDC login states and sessions using the durable tables added in the full-finish correction, atomically consumes login state with browser-binding and expiry checks, and reloads sessions through a fresh store wrapper. `api.Server.OIDCStore` now accepts the store interface instead of being type-locked to the in-memory implementation.

This is a durable v2 slice, not a live Authentik completion claim. Live Authentik provider/bootstrap/browser smoke and durable SCIM/token/app-password runtime wiring remain open.

Verification:

- Confirmed `go test ./internal/authn` passes with embedded Postgres SQL-store tests.
- Confirmed `go test ./internal/api ./internal/authn` passes after API store-interface wiring.
- Confirmed `git diff --check -- .` passes.
- Confirmed `go test -count=1 ./...` passes.

### 2026-07-18 CDT — Reopen v2-v4 full-finish work and close trust-boundary holes

Commit: f170729

Affected files:

- `internal/api/api.go`
- `internal/authn/oidc.go`
- `internal/authn/sql_store.go`
- `internal/authn/sql_store_test.go`
- `internal/api/api_test.go`
- `internal/api/scim.go`
- `internal/api/webmail.go`
- `internal/httpui/httpui.go`
- `internal/httpui/httpui_test.go`
- `internal/identity/identity.go`
- `internal/store/store.go`
- `internal/store/store_test.go`
- `internal/store/sql_test.go`
- `internal/webmail/webmail.go`
- `migrations/0001_initial.sql`
- `workflow.toml`
- `workflow/COVERAGE.md`
- `workflow/features/v2.identity-provisioning/live-authentik-persistence/README.md`
- `workflow/features/v2.identity-provisioning/live-authentik-persistence/evidence/2026-07-18-full-finish-blockers.md`
- `workflow/features/v3.ops-import-admin/production-ops/README.md`
- `workflow/features/v3.ops-import-admin/production-ops/evidence/2026-07-18-full-finish-blockers.md`
- `workflow/features/v4.webmail/production-webmail/README.md`
- `workflow/features/v4.webmail/production-webmail/evidence/2026-07-18-full-finish-blockers.md`

Explanation:

Danny rejected "enough" as the quality bar. This change stops representing v2/v3/v4 as fully done while major production integrations remain missing. The workflow root states for v2 identity provisioning, v3 ops/import/admin, and v4 webmail are reopened, the active feature returns to the v2 full-finish work, and explicit finishing features are added for live Authentik/durable persistence, production ops/import/backup/audit/snapshot work, and production webmail.

The patch also closes concrete trust-boundary holes found during full-finish audits. App-password listing now requires scoped mailbox read authorization. The legacy audit event list route now requires ops-admin bearer authorization and redacts events before returning them. Webmail draft submit now checks draft ownership against the authenticated mailbox scope before submission, so a leaked draft ID cannot cross mailbox boundaries. UI mutation routes now require bearer authorization instead of fabricating `local_admin ui`, and the backup verification UI no longer manufactures a fake verified artifact when no backup storage is configured.

Durable schema contracts were added for OIDC login state, sessions, backup artifacts/verifications, snapshots, and mailbox-owned webmail drafts, with embedded Postgres tests proving the tables and key constraints exist. OIDC state/session storage now has a real `authn.StateStore` interface and SQL-backed implementation; embedded Postgres tests prove state single-use, expiry rejection, browser binding, and session reload through a fresh store wrapper. This does not claim that all runtime services are fully wired to durable SQL yet; the blocker evidence states that remaining work explicitly.

Verification:

- Confirmed `go test -count=1 ./internal/api ./internal/httpui ./internal/store ./internal/identity ./internal/webmail ./internal/ops` passes.
- Confirmed `go test ./internal/authn` passes with SQL-backed OIDC store tests.
- Full repository verification is run before commit.

### 2026-07-18 CDT — Repair v2-v4 admission blockers in vertical slices

Commit: a7225af

Affected files:

- `internal/authn/oidc.go`
- `internal/authn/oidc_test.go`
- `internal/api/api.go`
- `internal/api/api_test.go`
- `internal/api/v3.go`
- `internal/api/webmail.go`
- `internal/authz/authz.go`
- `internal/daemon/daemon.go`
- `internal/httpui/httpui_test.go`
- `internal/identity/identity.go`
- `internal/identity/identity_test.go`
- `internal/ops/v3.go`
- `internal/webmail/webmail.go`
- `internal/webmail/webmail_test.go`
- `workflow/COVERAGE.md`
- `workflow/features/v2.identity-provisioning/evidence/2026-07-18-admission-repair.md`
- `workflow/features/v3.ops-import-admin/evidence/2026-07-18-admission-repair.md`
- `workflow/features/v4.webmail/evidence/2026-07-18-admission-repair.md`

Explanation:

Repaired the rejected v2/v3/v4 admission gates in layered vertical slices instead of broad horizontal cleanup. The v2 slice replaces direct caller-supplied `id_token` login with an authorization-code exchange seam, hardens session-cookie callback behavior, makes identity/provisioning mutations fail closed on audit write failure, and removes wildcard cross-mailbox API-token authority for app-password routes. The v3 slice authenticates and authorizes operator API routes, removes forged snapshot status, redacts audit event reads, rejects empty bulk-operation scope, writes per-item bulk audit records before mutation, and tightens Mailu candidate/verifier validation. The v4 slice wires webmail into authenticated mailbox-scoped API routes, binds mailbox reads and draft From values to `mailbox:<address>:webmail:use` token scope, enforces resolver-before-signer exact-sender binding, builds safer MIME with required sender/recipient/date headers and CRLF injection rejection, bounds search at the IMAP seam, prevents draft ID collisions, and downgrades hostile HTML to conservative escaped text rendering rather than pretending regex sanitization is a security boundary.

This entry does not claim live Authentik, Mailu, IMAP, SMTP, or OpenPGP cryptographic integration. Those gaps remain recorded in workflow evidence and the coverage map.

Verification:

- Confirmed `go test ./internal/api` passes after v3 and v4 API wiring repairs.
- Confirmed `go test ./internal/ops` passes after v3 import/bulk validation repairs.
- Confirmed `go test ./internal/webmail` passes after v4 MIME/search/draft/exact-sender seam repairs.
- Confirmed `git diff --check -- .` passes.
- Confirmed `go test ./...` passes.

### 2026-07-16 22:50 CDT — Add OpenPGP exact-sender drafts to PRD and specs

Commit: e39a402

Affected files:

- `docs/reference/openpgp-exact-sender/README.md`
- `docs/reference/openpgp-exact-sender/draft-hunn-openpgp-exact-sender-signatures-01.md`
- `docs/reference/openpgp-exact-sender/draft-hunn-exact-sender-operational-identity-history-00.md`
- `docs/prd/PRD.md`
- `docs/prd/PRD-v4-webmail.md`
- `docs/prd/PRD-v5-notifications.md`
- `docs/architecture/ARCHITECTURE.md`
- `docs/architecture/v4-webmail.md`
- `docs/architecture/v5-notifications.md`
- `docs/implementation/IMPLEMENTATION.md`
- `docs/implementation/v4-webmail.md`
- `docs/implementation/v5-notifications.md`
- `workflow.events.jsonl`

Explanation:

Added the split OpenPGP exact-sender drafts as repository reference material and wired them into the GopherMailForge PRD, architecture, and implementation-spec layers. The core exact-sender draft now anchors outbound OpenPGP/MIME signing, exact key-to-sender binding, delegation, and fail-closed behavior. The operational identity-history draft anchors temporal identity state, address/name history, search/audit indexing, downgrade detection, key-rotation continuity, and forensic export where those capabilities are implemented.

This change is documentation/spec traceability only. It does not claim the current v4 seam cut implements the full drafts, and it does not mark any workflow state done.

Verification:

- Confirmed `.md` reference drafts were copied into `docs/reference/openpgp-exact-sender/`.
- Confirmed PRD, architecture, and implementation specs link to the exact-sender drafts.
- Confirmed `git diff --check -- .` passes.
- Confirmed `go test ./...` passes.

### 2026-07-16 13:15 CDT — Admit v4 custom webmail protocol seams

Commit: f599e15

Affected files:

- `internal/webmail/webmail.go`
- `internal/webmail/webmail_test.go`
- `docs/CHANGELOG.md`
- `workflow.toml`
- `workflow.events.jsonl`
- `workflow/features/v4.webmail/README.md`
- `workflow/features/v4.webmail/provider-imap-compose/README.md`
- `workflow/features/v4.webmail/provider-imap-compose/evidence/2026-07-16-provider-imap-compose.md`
- `workflow/features/v4.webmail/search-security-ux/README.md`
- `workflow/features/v4.webmail/search-security-ux/evidence/2026-07-16-search-security-ux.md`
- `workflow/features/v4.webmail/evidence/2026-07-16-v4-root-completion.md`

Explanation:

Admitted the v4 custom webmail protocol seam implementation by owner direction: external-provider continuity, folder list, message list/read, pagination/windowing, quota display, current-folder search, draft save, submit, send failure reporting, and mandatory OpenPGP/MIME signing structure validation for outbound sends. The webmail sender rejects unsigned or mismatched signing identity attempts and records audit metadata without treating OIDC as SMTP.

Added MIME/HTML safety foundations: script stripping, event-handler blocking, javascript URL blocking, remote image blocking, CSP baseline, attachment filename traversal sanitization, and oversized attachment fallback behavior. Webmail remains a provider/client model and does not replace Dovecot/SMTP or mutate control-plane state directly.

Verification:

- Confirmed `go test ./internal/webmail` passes for admitted seam/model coverage.
- Cold review rejected this as full production webmail; owner-directed admission accepts the seam cut with known gaps recorded in workflow evidence.
- Confirmed `git diff --check -- .` passes.
- Confirmed `go test ./...` passes.

### 2026-07-16 12:55 CDT — Implement v3 ops, import, and mature admin workflows

Commit: efbfa3b

Affected files:

- `cmd/gmf/main.go`
- `cmd/gmf/main_test.go`
- `internal/api/api.go`
- `internal/api/api_test.go`
- `internal/api/v3.go`
- `internal/httpui/httpui.go`
- `internal/httpui/httpui_test.go`
- `internal/ops/v3.go`
- `internal/ops/v3_test.go`
- `docs/CHANGELOG.md`
- `workflow.toml`
- `workflow.events.jsonl`
- `workflow/features/v3.ops-import-admin/README.md`
- `workflow/features/v3.ops-import-admin/audit-backup-snapshots/README.md`
- `workflow/features/v3.ops-import-admin/audit-backup-snapshots/evidence/2026-07-16-audit-backup-snapshots.md`
- `workflow/features/v3.ops-import-admin/mailu-import/README.md`
- `workflow/features/v3.ops-import-admin/mailu-import/evidence/2026-07-16-mailu-import.md`
- `workflow/features/v3.ops-import-admin/abuse-bulk-ui/README.md`
- `workflow/features/v3.ops-import-admin/abuse-bulk-ui/evidence/2026-07-16-abuse-bulk-ui.md`
- `workflow/features/v3.ops-import-admin/evidence/2026-07-16-v3-root-completion.md`

Explanation:

Implemented v3 operator surfaces for audit filtering/export/retention, backup verification, snapshot rollback guidance, Mailu import preview/apply, abuse/rate-limit/deferred correlation, and mature bulk admin workflows. Preview/apply flows now keep server-side import and bulk preview/job state instead of trusting caller-supplied preview bodies. Backup verification reads a storage artifact, restores into an isolated modeled state, runs schema migration checks, and validates daemon contracts before marking a backup verified. Rollback guidance refuses fake safety without verified restore state.

Mailu import preview classifies unsupported/weakening inputs, rejects plaintext secrets and unsupported verifier algorithms, requires source fingerprint/hash/actor/expiry binding, exposes `GET /api/v1/imports/{id}`, and audits apply. Bulk workflows whitelist operations, store previews/jobs server-side, require confirmation/hash/actor/expiry checks, emit per-item audit events, and expose `GET /api/v1/bulk/jobs/{id}`. v3 UI sections include working backup verify, Mailu preview, and bulk preview forms rather than dead links.

Verification:

- Confirmed `go test ./cmd/gmf` passes.
- Confirmed `go test ./internal/ops` passes.
- Confirmed `go test ./internal/api` passes.
- Confirmed `go test ./internal/httpui` passes.
- Confirmed `git diff --check -- .` passes.
- Confirmed `go test ./...` passes.

### 2026-07-16 12:05 CDT — Finish v2 identity provisioning

Commit: fc2ce0e

Affected files:

- `internal/identity/identity.go`
- `internal/identity/identity_test.go`
- `internal/api/api.go`
- `internal/api/api_test.go`
- `internal/api/scim.go`
- `internal/daemon/daemon.go`
- `internal/daemon/daemon_test.go`
- `internal/httpui/httpui.go`
- `internal/httpui/httpui_test.go`
- `docs/CHANGELOG.md`
- `workflow.toml`
- `workflow.events.jsonl`
- `workflow/features/v2.identity-provisioning/README.md`
- `workflow/features/v2.identity-provisioning/oidc-sessions/README.md`
- `workflow/features/v2.identity-provisioning/scim/README.md`
- `workflow/features/v2.identity-provisioning/scim/evidence/2026-07-16-scim.md`
- `workflow/features/v2.identity-provisioning/app-passwords-ui/README.md`
- `workflow/features/v2.identity-provisioning/app-passwords-ui/evidence/2026-07-16-app-passwords-ui.md`
- `workflow/features/v2.identity-provisioning/evidence/2026-07-16-v2-root-completion.md`

Explanation:

Completed the v2 identity/provisioning root. This change adds the remaining SCIM provisioning API, identity service, app-password/mail-client token behavior, Dovecot verifier integration, and identity UI surfaces. SCIM now exposes service metadata and Users list/create/read/replace/patch/disable behavior, requires verifier-backed bearer-token authentication for user routes, returns explicit unsupported Groups responses, validates payload/domain/password/patch failures, writes Django PBKDF2-SHA256 verifier strings for supplied mailbox passwords, synchronizes provisioned users into the daemon mailbox/passdb view, and emits audit events for provisioning mutations and denied/failure paths.

App passwords now support create/list/revoke through API routes. Create returns the plaintext generated secret once. Stored records retain verifier hashes only, app-password API routes require verifier-backed bearer-token authentication, list responses do not disclose plaintext secrets or verifier strings, revocation prevents future daemon `DovecotPassdb` verification, and mailbox/app-password verification uses the same Django-compatible verifier contract.

The identity UI now exposes OIDC/Auth, Authentik role mapping, SCIM status/test, app-password list/create/revoke, and permission simulator screens; SCIM test provisioning, app-password, and simulator UI flows use service authorization/audit paths. Workflow state marks all v2 children and the v2 root done, then advances the active feature to the first v3 child.

Verification:

- Confirmed `go test ./internal/identity` passes.
- Confirmed `go test ./internal/api` passes.
- Confirmed `go test ./internal/httpui` passes.
- Confirmed `git diff --check -- .` passes.
- Confirmed `go test ./...` passes.

### 2026-07-16 11:52 CDT — Add Authentik role mapping and permission simulator coverage

Commit: 33eedc5

Affected files:

- `internal/authz/authz.go`
- `internal/authz/authz_test.go`
- `internal/api/api.go`
- `internal/api/api_test.go`
- `internal/ops/ops.go`
- `internal/ops/ops_test.go`
- `docs/CHANGELOG.md`
- `workflow.toml`
- `workflow.events.jsonl`
- `workflow/features/v2.identity-provisioning/authentik-roles-authz/README.md`
- `workflow/features/v2.identity-provisioning/authentik-roles-authz/evidence/2026-07-16-authentik-roles-authz.md`

Explanation:

Implemented the Authentik role-mapping child for v2 identity provisioning. OIDC actors now carry Authentik groups and are evaluated against verified role mappings for global admin, domain manager, and scoped domain access. Authorization explanations now include matched rules for allowed decisions and missing requirements for denied decisions, so the permission simulator can explain the actual mechanism instead of returning a hardcoded local-admin answer.

The `/api/v1/authz/explain` route now decodes the submitted actor/action/resource request and evaluates it. Doctor now validates required role mappings and fails loudly when required mappings are missing, unverified, or reference unknown domains.

Verification:

- Confirmed `go test ./...` passes.
- Confirmed `git diff --check -- .` passes.

### 2026-07-16 11:05 CDT — Implement v2 OIDC sessions

Commit: b887c75

Affected files:

- `internal/authn/oidc.go`
- `internal/authn/oidc_test.go`
- `internal/api/api.go`
- `internal/api/api_test.go`
- `workflow.toml`
- `workflow.events.jsonl`
- `workflow/features/v2.identity-provisioning/oidc-sessions/evidence/2026-07-16-oidc-sessions.md`

Explanation:

Completed the first v2 child, `v2.identity-provisioning.oidc-sessions`. The implementation adds OIDC discovery validation, login state and nonce generation, authorization URL construction, exact redirect URI validation, browser-bound single-use callback state consumption, RS256 ID-token signature verification against JWKS, strict issuer/subject/audience/azp/exp/iat/nbf/nonce claim validation, session creation, and safe token-free error handling. API surfaces expose login start and callback validation without treating OIDC as IMAP/SMTP authentication.

The feature explicitly rejects unsigned `alg=none` tokens and has no unsigned-claim fallback. The next active v2 child is Authentik role mapping and permission simulator coverage.

Verification:

- Must pass `go test ./...`.
- Must pass `git diff --check -- .`.

### 2026-07-16 10:50 CDT — Start v2 identity provisioning

Commit: 43a56ca

Affected files:

- `workflow.toml`
- `workflow.events.jsonl`
- `workflow/features/v2.identity-provisioning/oidc-sessions/evidence/2026-07-16-start.md`

Explanation:

Started the v2 identity/provisioning root from the merged v1 admission baseline. The active child is `v2.identity-provisioning.oidc-sessions`, covering OIDC authorization-code login, single-use state, nonce/redirect validation, signed token validation through the configured issuer/JWKS, session behavior, no unsigned-claim fallback, and no token disclosure.

Verification:

- Must pass `git diff --check -- .`.
- Must pass `go test ./...`.

### 2026-07-16 10:22 CDT — Clarify exact-user OpenPGP identity binding

Commit: fcfdcdf

Affected files:

- `docs/prd/PRD.md`
- `docs/prd/PRD-v4-webmail.md`
- `docs/architecture/v4-webmail.md`
- `docs/implementation/v4-webmail.md`
- `docs/prd/PRD-v5-notifications.md`
- `docs/architecture/v5-notifications.md`
- `docs/implementation/v5-notifications.md`
- `workflow.toml`
- `workflow/COVERAGE.md`
- `workflow/features/v5.notifications/openpgp-signed-email/evidence/2026-07-16-openpgp-requirement.md`

Explanation:

Tightened the OpenPGP requirement so it cannot be misread as domain provenance. DKIM answers which domain/server handled a message; GopherMailForge requires exact-user-origin proof. Every outbound email signature must verify to exactly one configured active user or system notification identity, and that identity must be allowed to assert the message `From`/`Sender`. Ambiguous, unmapped, shared, revoked, expired, disabled, or mismatched signing keys fail closed and are treated as unsigned/invalid.

Verification:

- Must pass `git diff --check -- .`.
- Must pass `go test ./...`.

### 2026-07-16 10:21 CDT — Require OpenPGP signing for every outbound email

Commit: 6e3d5e1

Affected files:

- `docs/prd/PRD.md`
- `docs/prd/PRD-v4-webmail.md`
- `docs/architecture/v4-webmail.md`
- `docs/implementation/v4-webmail.md`
- `docs/prd/PRD-v5-notifications.md`
- `docs/architecture/v5-notifications.md`
- `docs/implementation/v5-notifications.md`
- `workflow.toml`
- `workflow/COVERAGE.md`
- `workflow.events.jsonl`
- `workflow/features/v5.notifications/openpgp-signed-email/README.md`
- `workflow/features/v5.notifications/openpgp-signed-email/evidence/2026-07-16-openpgp-requirement.md`

Explanation:

Made Danny's OpenPGP requirement canonical: every outbound email must be OpenPGP/MIME signed. DKIM remains required as domain/server proof, but it is not accepted as user-origin proof. Missing, revoked, expired, disabled, mismatched, or failed signing keys block send. The system must not silently fall back to unsigned email for convenience, notification delivery, resend, approval, or automated mail.

The requirement is recorded as a global product invariant, tied into v4 compose/send behavior, and added to v5 notification/email backend scope through a new planned feature `v5.notifications.openpgp-signed-email`. Verification requirements now include OpenPGP/MIME signed outbound email tests, no-unsigned-fallback tests, key-state rejection tests, identity mismatch tests, and audit fingerprint/signature-status tests.

Verification:

- Must pass `git diff --check -- .`.
- Must pass `go test ./...`.

### 2026-07-16 09:03 CDT — Finish v1 mail core root

Commit: a75b0f1

Affected files:

- `cmd/gmf/main.go`
- `cmd/gmf/main_test.go`
- `cmd/gophermailforge/main.go`
- `internal/admin/admin.go`
- `internal/admin/admin_test.go`
- `internal/api/api.go`
- `internal/httpui/httpui.go`
- `internal/httpui/httpui_test.go`
- `internal/plugin/seams.go`
- `internal/plugin/seams_test.go`
- `scripts/reference-runtime-smoke.sh`
- `test/contract/v1_plugins_contract_test.go`
- `workflow.toml`
- `workflow.events.jsonl`
- `workflow/COVERAGE.md`
- `workflow/features/v1.mail-core/evidence/2026-07-16-v1-root-completion.md`
- `workflow/features/v1.mail-core/review/2026-07-16-root-admission-review-final.md`
- v1 evidence/changelog files with historical commit-hash cleanup

Explanation:

Finished the v1 mail-core root after a cold admission review rejected the previous branch as overclaimed. The real Postfix/Dovecot/Rspamd/Roundcube reference smoke was already passing, but v1 still lacked root admission integrity and several declared v1 surfaces. This change adds the missing `gmf doctor --format text|json` CLI, a minimal server-rendered mail admin UI with domain/user/alias CRUD backing store, DNS/DKIM/doctor/lookup/plugin screens, seam-specific first-plugin service contracts for DNS export, certificate/manual ACME failure, backup verification, and Roundcube webmail config, and reference-runtime doctor proof that ACME/manual-cert behavior fails loudly instead of pretending success for `example.test`.

The reference smoke SMTP sections now use deterministic Python `smtplib` clients rather than timing-sensitive `printf | nc` scripting. Historical v1 changelog and evidence placeholders were replaced with real commit hashes. `workflow.toml` now marks `v1.mail-core` done and records root completion evidence/review.

Verification:

- Must pass `go test ./...`.
- Must pass `git diff --check -- .`.
- Must pass `scripts/reference-runtime-smoke.sh` against the reference Compose stack.

### 2026-07-16 02:11 CDT — Add v1 reference runtime smoke

Commit: 9f1aa30fb3920aa2ba4ccc30ed3cdf6088de3d5a

Affected files:

- `cmd/gophermailforge/main.go`
- `compose/reference/docker-compose.yml`
- `compose/reference/dovecot/dovecot.conf`
- `compose/reference/postfix/main.cf`
- `compose/reference/postfix/virtual_aliases`
- `compose/reference/postfix/virtual_mailboxes`
- `compose/reference/rspamd/local.d/dkim_signing.conf`
- `compose/reference/rspamd/local.d/worker-controller.inc`
- `compose/reference/rspamd/local.d/worker-normal.inc`
- `compose/reference/rspamd/local.d/worker-proxy.inc`
- `scripts/reference-runtime-smoke.sh`
- `test/contract/v1_plugins_contract_test.go`
- `workflow.toml`
- `workflow.events.jsonl`
- `workflow/COVERAGE.md`
- `workflow/features/v1.mail-core/reference-runtime-smoke/README.md`
- `workflow/features/v1.mail-core/reference-runtime-smoke/evidence/2026-07-16-reference-runtime-smoke.md`
- `workflow/features/v1.mail-core/review/2026-07-16-root-admission-review.md`

Explanation:

Added the narrow `v1.mail-core.reference-runtime-smoke` child required by root admission review. Reference Compose now runs real Postfix, Dovecot, Rspamd, and selected Roundcube external webmail provider service against a seeded GopherMailForge reference fixture instead of only modeling daemon contracts. The smoke harness starts the Compose stack, checks the internal daemon HTTP/JSON contracts, proves Postfix recipient policy uses the GopherMailForge policy socket by rejecting `nobody@example.test`, sends a real SMTP message to `alias@example.test`, proves alias delivery into the `smoke@example.test` Maildir, logs in over real Dovecot IMAP using generated GopherMailForge-derived auth/userdb material, fetches the delivered subject, logs into Roundcube over HTTP and verifies the delivered message appears through Roundcube’s IMAP-backed mail view, and proves Rspamd is in the Postfix milter path by requiring `DKIM-Signature` on the delivered message plus valid DKIM material/config.

This fixes the root blocker recorded by the previous v1 admission review, but it does not itself admit the root. A fresh cold root review should inspect this commit before opening a v1 admission PR.

Verification:

- Confirmed `go test ./...` passes.
- Confirmed `git diff --check -- .` passes.
- Confirmed `scripts/reference-runtime-smoke.sh` passes against the real reference Compose stack.

### 2026-07-16 01:56 CDT — Add v1 diagnostics, queue, smoke-result, and snapshot surfaces

Commit: f7f8162c93dac3f7ddc024c135936d553db09fbc

Affected files:

- `docs/CHANGELOG.md`
- `internal/api/api.go`
- `internal/api/api_test.go`
- `internal/ops/ops.go`
- `internal/ops/ops_test.go`
- `workflow.toml`
- `workflow.events.jsonl`
- `workflow/COVERAGE.md`
- `workflow/features/v1.mail-core/diagnostics-smoke-snapshots/evidence/2026-07-16-diagnostics-smoke-snapshots.md`

Explanation:

Completed the `v1.mail-core.diagnostics-smoke-snapshots` child by adding machine-readable doctor aggregation, lookup debugging, mail-flow trace modeling, queue visibility/mutations, smoke-result modeling, and snapshot capture. Queue flush/retry require explicit confirmations and emit audit events. Snapshots are explicitly marked as not rollback, avoiding fake safety. The API handler now exposes doctor, debug lookup, queue summary/deferred, and queue flush/retry routes.

This does not mark the v1 root complete. The implementation includes smoke-result modeling but has not yet proven a live reference Compose SMTP/IMAP/DKIM/webmail mail-flow smoke with real daemons. That root gap is recorded in workflow evidence and the global coverage map.

Verification:

- Confirmed `go test ./...` passes.
- Added tests for doctor status aggregation, lookup/debug trace shape, queue confirmation/audit behavior, snapshot-not-rollback semantics, and API route wiring.

### 2026-07-16 01:50 CDT — Add first v1 mechanism plugin containers

Commit: 6456a60cb0a5d86ea2ceb4bf83d9ae5e8fa6f8bf

Affected files:

- `Dockerfile`
- `cmd/gmf-plugin/main.go`
- `compose/reference/docker-compose.yml`
- `docs/CHANGELOG.md`
- `internal/plugin/first.go`
- `internal/plugin/first_test.go`
- `test/contract/v1_plugins_contract_test.go`
- `workflow.toml`
- `workflow.events.jsonl`
- `workflow/COVERAGE.md`
- `workflow/features/v1.mail-core/first-plugins/evidence/2026-07-16-first-plugins.md`

Explanation:

Completed `v1.mail-core.first-plugins` by adding the first mechanism plugin identities and reference container wiring for the selected external webmail provider, manual DNS export, manual/Let’s Encrypt certificate handling, and local filesystem backup storage. The new `gmf-plugin` runner exposes the existing v0 generated protobuf/gRPC `PluginControl` service, so first plugins authenticate with service identity metadata, require deadlines, and report capabilities through the same control contract as the rest of the plugin runtime.

The reference Compose file now includes all four plugin services and still avoids Docker socket mounts. The backup plugin receives only a named `/backup` volume. This patch intentionally does not pretend the seam-specific DNS/cert/backup/webmail APIs are complete; it establishes the first plugin container/control-plane surface and records the remaining live integration work as future scope.

Verification:

- Confirmed `go test ./...` passes.
- Added tests for first plugin seams/capabilities, authenticated and unauthenticated gRPC control behavior, Dockerfile plugin runner output, required Compose services, and absence of Docker socket mounts.

### 2026-07-16 01:45 CDT — Add v1 DNS/TLS/ACME diagnostics

Commit: 6b8fa6603a0e47580dbc3c6996c6f9a8397aec2b

Affected files:

- `docs/CHANGELOG.md`
- `internal/diag/dns_tls.go`
- `internal/diag/dns_tls_test.go`
- `workflow.toml`
- `workflow.events.jsonl`
- `workflow/COVERAGE.md`
- `workflow/features/v1.mail-core/dns-tls-acme/evidence/2026-07-16-dns-tls-acme.md`

Explanation:

Completed `v1.mail-core.dns-tls-acme` by adding the diagnostic primitives for exact DNS readiness, TLS certificate validation, MTA-STS/TLS-RPT generation, and loud ACME failure reporting. DNS checks now return the documented status enum with expected values, observed values, and remediation text instead of hand-wavy readiness booleans. TLS checks parse certificates, validate expiry windows, and fail on missing SAN coverage. ACME failure construction is explicit and actionable rather than silently falling back to self-signed behavior.

This is deliberately not the full doctor or live ACME plugin. Those belong to later v1 children. This patch provides the deterministic mechanism and tests they will consume.

Verification:

- Confirmed `go test ./...` passes.
- Added tests for DNS present/missing/mismatch/unsupported states, MTA-STS/TLS-RPT generation, certificate OK/warn/expired/SAN-mismatch behavior, and loud ACME failure output.

### 2026-07-16 01:41 CDT — Generate daemon config for v1 mail core

Commit: d77df0eef449559f03f4075cfe1b35b84590c95c

Affected files:

- `docs/CHANGELOG.md`
- `internal/render/render.go`
- `internal/render/render_test.go`
- `workflow.toml`
- `workflow.events.jsonl`
- `workflow/COVERAGE.md`
- `workflow/features/v1.mail-core/generated-config/evidence/2026-07-16-generated-config.md`

Explanation:

Completed `v1.mail-core.generated-config` by expanding the deterministic render set with daemon-facing generated config files for front/proxy, Postfix, Dovecot, Rspamd, and the selected external webmail provider placeholder. Generated daemon config now points the daemon mechanisms at the v1 internal HTTP/JSON contract endpoints from `v1.mail-core.daemon-contracts` instead of leaving the rendered output as only v0 control-plane/plugin files.

Every generated file now uses the v1 source header form with the generated config set ID and input hash. The render ID is computed from sorted file paths and bodies before source headers are stamped, avoiding a dishonest circular hash while still giving operators traceability from files back to the generated set. Existing staged render/apply behavior remains intact with the larger render set.

Updated workflow state to mark `v1.mail-core.generated-config` done and recorded feature evidence plus the global coverage posture.

Verification:

- Confirmed `go test ./...` passes.
- Confirmed `git diff --check -- .` passes.
- Added render tests proving daemon config files exist and carry `generated_config_set` plus `input_hash` source headers.

### 2026-07-16 01:37 CDT — Implement v1 daemon contract surface

Commit: 824faf10b78352124887aa654bac3f8518ae59fe

Affected files:

- `docs/CHANGELOG.md`
- `go.mod`
- `go.sum`
- `internal/api/api.go`
- `internal/api/api_test.go`
- `internal/daemon/daemon.go`
- `internal/daemon/daemon_test.go`
- `internal/daemon/http.go`
- `internal/daemon/http_test.go`
- `workflow.toml`
- `workflow.events.jsonl`
- `workflow/COVERAGE.md`
- `workflow/features/v1.mail-core/daemon-contracts/evidence/2026-07-16-daemon-contracts.md`

Explanation:

Started v1 mail-core after v0 admission by implementing the first manifest child, `v1.mail-core.daemon-contracts`. This adds the internal HTTP/JSON daemon contract surface used by Postfix, Dovecot, and Rspamd. The implementation uses explicit daemon decisions (`ok`, `not_found`, `reject`, `defer`, `error`), correlation IDs, reason codes, and safe diagnostic messages rather than fake success or stringly hidden failures.

Postfix contract coverage now includes domain, recipient, mailbox, alias, sender-login, sender-policy, rate-limit, and transport behavior. Dovecot coverage now includes passdb, userdb, quota, and default sieve behavior, including Authentik/Django-compatible PBKDF2-SHA256 verifier checks and explicit rejection of OIDC tokens as IMAP/SMTP credentials. Rspamd coverage now includes local domains, DKIM key runtime path lookup, signing decisions, and rate signals. The main API handler now registers the `/internal/v1/postfix/*`, `/internal/v1/dovecot/*`, and `/internal/v1/rspamd/*` routes.

Updated workflow state to make `v1.mail-core.daemon-contracts` the active completed child and `v1.mail-core` in progress. Updated workflow evidence and the global coverage map with the remaining v1 gaps assigned to later planned children.

Verification:

- Confirmed `go test ./...` passes.
- Added contract tests for Postfix happy/failure paths, Dovecot passdb/userdb/quota behavior, Rspamd DKIM/local-domain behavior, malformed JSON/method gates, correlation propagation, and API route wiring.

### 2026-07-16 01:23 CDT — Fix v0 admission blockers from cold review

Commit: 7e6633f

Affected files:

- `cmd/gmf/main.go`
- `cmd/gmf/main_test.go`
- `docs/CHANGELOG.md`
- `go.mod`
- `go.sum`
- `internal/api/api.go`
- `internal/api/api_test.go`
- `internal/apply/apply.go`
- `internal/audit/audit.go`
- `internal/config/config.go`
- `internal/config/config_test.go`
- `internal/plugin/grpc.go`
- `internal/plugin/grpc_test.go`
- `internal/plugin/plugin.go`
- `internal/plugin/plugin_test.go`
- `internal/render/render.go`
- `internal/store/sql.go`
- `internal/store/sql_test.go`
- `internal/store/store.go`
- `migrations/0001_initial.sql`
- `proto/gophermailforge/plugin/v1/plugin.pb.go`
- `proto/gophermailforge/plugin/v1/plugin_grpc.pb.go`
- `workflow/COVERAGE.md`
- `workflow/features/v0.foundation/evidence/2026-07-14-v0-foundation-implementation.md`

Explanation:

Fixed the concrete v0 admission blockers found by cold review instead of merging a stub foundation. The CLI render/diff/apply path now uses real file-backed staged state: render writes a content-addressed staged directory, diff compares the staged set against the currently applied set, and apply requires an operator-provided `--confirm <staged-id>` before marking the generated set as applied. The apply library can now persist the applied marker in the configured applied directory while preserving audit emission.

The HTTP API shell now exposes the required v0 control-plane routes for effective config, render, render diff, render apply, audit event listing, plugin listing, plugin health, status, health/readiness, and authz explain, with method gates instead of silent success. Audit persistence now includes source IP and user-agent fields and a SQL-backed writer that stores redacted before/after payloads. The initial Postgres schema now enforces documented enum/status/seam constraints and rejects enabled plugin registrations without service identity credentials where the database can enforce it directly.

The config loader now uses a real YAML decoder with known-field rejection instead of a hand-rolled colon scanner, including rejection of unknown nested plugin keys. The plugin control transport now uses generated protobuf/gRPC bindings from `plugin.proto`, metadata for correlation/service identity, context deadlines, and canonical gRPC status codes rather than private JSON structs and string errors.

Verification:

- Confirmed `go test ./...` passes after the admission fixes.
- Added regression coverage for staged CLI render/apply confirmation behavior, required API shell routes, SQL audit source persistence, database constraints, YAML unknown-field rejection, and protobuf/metadata/status-code gRPC behavior.

### 2026-07-14 23:59 CDT — Replace SQLite migration harness with embedded Postgres

Commit: 55c9302

Affected files:

- `docs/CHANGELOG.md`
- `go.mod`
- `go.sum`
- `internal/store/sql.go`
- `internal/store/sql_test.go`
- `workflow/COVERAGE.md`
- `workflow/features/v0.foundation/evidence/2026-07-14-v0-foundation-implementation.md`

Explanation:

Corrected the v0 migration test harness after review caught that SQLite was the wrong database target. GopherMailForge's v0 docs and Compose topology use Postgres, and the intended direction is embedded Postgres for local/test verification. SQLite is a different database with different type, constraint, locking, default, and SQL dialect behavior; passing SQLite migration tests would be false confidence.

This change removes the SQLite harness and uses `github.com/fergusstrange/embedded-postgres` plus `github.com/lib/pq` to start a real embedded Postgres instance in the migration test. The test now applies the v0 schema through Postgres, verifies migration-history rows, verifies the domain uniqueness constraint, and verifies mailbox foreign-key rejection against actual Postgres behavior. The migration executor now uses Postgres-style `$1` placeholders.

Verification:

- Confirmed embedded Postgres migration test starts a real local Postgres instance and verifies migration history, unique constraint rejection, and foreign-key rejection.
- Confirmed full `go test ./...` passes.
- Confirmed `sudo docker build -t gophermailforge:v0-smoke .` passes with build-stage tests running as the unprivileged `gmf` user.
- Confirmed `git diff --check -- .` passes.

### 2026-07-15 00:03 CDT — Harden v0 migration and plugin transport tests

Commit: `b36612b3e5aeeed50b1906d082174938887f0cc3`

Affected files:

- `Dockerfile`
- `docs/CHANGELOG.md`
- `go.mod`
- `go.sum`
- `internal/plugin/grpc.go`
- `internal/plugin/grpc_test.go`
- `internal/store/sql.go`
- `internal/store/sql_test.go`
- `workflow/COVERAGE.md`
- `workflow/features/v0.foundation/evidence/2026-07-14-v0-foundation-implementation.md`

Explanation:

Strengthened the v0 foundation implementation after review exposed two weak spots. The first pass had migration coverage that proved the schema list existed but did not execute the schema through a real SQL engine. It also had plugin control behavior as an in-process contract, with the protobuf file present but no actual gRPC transport skeleton test. That was too close to paperwork theater for a foundation release.

This change originally added SQLite-backed migration execution tests using `modernc.org/sqlite`, which was later corrected because the project database contract is Postgres. The gRPC server/client skeleton portion remains: it adds a registered JSON codec over gRPC and `bufconn` tests for authenticated and unauthenticated health calls. The protobuf file remains the contract layout; the transport skeleton now proves the health path crosses a real gRPC boundary instead of only a local function call.

The Go toolchain and Docker builder were aligned to Go 1.25 after dependency resolution raised the module version.

Verification:

- Confirmed `go test ./internal/plugin ./internal/store` passes after the hardening change.
- Full final project verification is recorded in the v0 evidence file and rerun before commit.

### 2026-07-14 23:56 CDT — Record v0 implementation commit hash

Commit: `ca8965fdb74135f19000e3fca8dec0d5f9483a27`

Affected files:

- `docs/CHANGELOG.md`

Explanation:

Updated the v0 implementation changelog entry with the real Git commit hash after Git assigned it. This is the honest way to satisfy the changelog requirement without pretending a commit can contain its own final hash.

Verification:

- Confirmed the v0 implementation entry now records commit `6cf655c37451a8da63e7360e5bde9b7b2664e176`.
- Confirmed `git diff --check -- .` passes.

### 2026-07-14 23:52 CDT — Implement v0 foundation

Commit: `6cf655c37451a8da63e7360e5bde9b7b2664e176`

Affected files:

- `Dockerfile`
- `cmd/gmf/main.go`
- `cmd/gophermailforge/main.go`
- `compose/reference/docker-compose.yml`
- `go.mod`
- `internal/api/api.go`
- `internal/api/api_test.go`
- `internal/apply/apply.go`
- `internal/apply/apply_test.go`
- `internal/audit/audit.go`
- `internal/audit/audit_test.go`
- `internal/authn/authn.go`
- `internal/authn/authn_test.go`
- `internal/authz/authz.go`
- `internal/authz/authz_test.go`
- `internal/config/config.go`
- `internal/config/config_test.go`
- `internal/httpui/httpui.go`
- `internal/plugin/plugin.go`
- `internal/plugin/plugin_test.go`
- `internal/render/render.go`
- `internal/render/render_test.go`
- `internal/store/store.go`
- `internal/store/store_test.go`
- `internal/version/version.go`
- `migrations/0001_initial.sql`
- `proto/gophermailforge/plugin/v1/plugin.proto`
- `test/contract/sample-config.yaml`
- `test/contract/v0_contract_test.go`
- `test/fixtures/mail.crt`
- `test/fixtures/mail.key`
- `workflow/COVERAGE.md`
- `workflow.events.jsonl`
- `workflow.toml`
- `workflow/features/v0.foundation/evidence/2026-07-14-v0-foundation-implementation.md`

Explanation:

Implemented the v0 foundation as a narrow control-plane baseline. This adds the Go module, server and CLI entrypoints, HTTP/API health/status/authz shell, GOTTH-compatible server-rendered UI shell, typed config parser and validator, TLS safety validation, deterministic render output, explicit apply gate, audit writer and redaction, static v0 authorization simulator, Authentik base model, initial schema/migration representation, plugin registry/control skeleton, protobuf contract layout, Dockerfile, reference Compose topology, contract fixtures, tests, workflow evidence, coverage updates, and workflow state updates for v0.

The implementation intentionally does not add v1 mail-daemon behavior, SCIM provisioning, full OIDC login, real plugin implementations, or custom webmail. v0 remains the foundation: it establishes package boundaries, validation, audit/authz behavior, render/apply mechanics, plugin contract seams, Authentik-adjacent topology, and verification harnesses.

The workflow manifest now marks `v0.foundation` and its v0 child features as done. Evidence for the verification commands and coverage posture is recorded under `workflow/features/v0.foundation/evidence/`.

Verification:

- Confirmed `go test ./...` passes.
- Confirmed explicit binary builds for `cmd/gmf` and `cmd/gophermailforge` pass.
- Confirmed CLI config validation, render, diff, apply, migrate, and authz smoke commands pass against `test/contract/sample-config.yaml`.
- Confirmed `sudo docker build -t gophermailforge:v0-smoke .` passes and runs `go test ./...` inside the build stage.
- Confirmed `git diff --check -- .` passes.

### 2026-07-14 23:31 CDT — Expand changelog entry requirements

Commit: `9d84ad3aa567a9579c73afb4c4b74b686ea9ec6c`

Affected files:

- `docs/CHANGELOG.md`
- `docs/implementation/IMPLEMENTATION.md`
- `workflow/README.md`
- `workflow.toml`

Explanation:

The first changelog pass was too terse. It recorded that a change happened, but it did not force the entry to carry enough review context. That is sloppy for a project that is using PRDs, architecture, implementation specs, workflow evidence, and detached worktrees as serious state. A changelog that only says "changed things" is decoration, not audit value.

This change makes the changelog format explicit. Each meaningful change now needs a date/time with timezone, commit identifier, affected files, verbose explanation, and verification summary. The rule also documents the unavoidable Git self-reference problem: the entry for the commit currently being created cannot contain its own final hash because the hash depends on the file content. Historical entries must use real hashes.

Verification:

- Confirmed verbose changelog fields are present.
- Confirmed markdown links resolve.
- Confirmed `workflow.toml` parses and points to `docs/CHANGELOG.md`.
- Confirmed `git diff --check -- .` passes.

### 2026-07-14 23:27 CDT — Add docs changelog discipline

Commit: `1dd7d7fff82940cfafc4934242631eafb68642ad`

Affected files:

- `README.md`
- `docs/CHANGELOG.md`
- `docs/implementation/IMPLEMENTATION.md`
- `workflow.toml`
- `workflow/README.md`

Explanation:

Added the project changelog under `docs/` and made it part of the documented development workflow. The repository already had PRDs, architecture docs, implementation specs, workflow records, and evidence folders, but it lacked a compact chronological index of meaningful changes. That was a real gap: reviewers would have to reconstruct project history from scattered commits and workflow artifacts.

The change links the changelog from the root README, adds implementation-level discipline requiring changelog updates for meaningful changes, records the changelog path in `workflow.toml`, and explains in `workflow/README.md` that workflow evidence remains separate from the changelog. The changelog is the human-readable index; it is not a substitute for tests, evidence, handoff notes, or verification.

Verification:

- Confirmed `docs/CHANGELOG.md` exists.
- Confirmed markdown links resolve.
- Confirmed `workflow.toml` parses.
- Confirmed `git diff --check -- .` passes.
- Fast-forwarded all six root worktrees to the commit.

### 2026-07-14 23:19 CDT — Require Authentik-compatible password hashes

Commit: `653b9e7a7e69cd2feaadd9c8abd82625e9ebe377`

Affected files:

- `README.md`
- `docs/architecture/v2-identity-provisioning.md`
- `docs/implementation/IMPLEMENTATION.md`
- `docs/implementation/v0-foundation.md`
- `docs/implementation/v1-mail-core.md`
- `docs/implementation/v2-identity-provisioning.md`
- `docs/implementation/v3-ops-import-admin.md`
- `docs/prd/PRD-v2-identity-provisioning.md`
- `docs/prd/PRD.md`
- `docs/reference/authentik-password-hashing.md`
- `workflow.toml`

Explanation:

Verified Authentik's actual password hashing behavior instead of guessing from dependency names. Source inspection showed Authentik uses Django 5.2 password hashing, does not define a project-local `PASSWORD_HASHERS` override in `authentik/root/settings.py`, validates imported password hashes with Django `identify_hasher(password_hash)`, and hashes passwords with Django `make_password(password)`. Django stores password hashes as encoded strings carrying the algorithm and parameters, such as `algorithm$iterations$salt$hash`; the default new-password hasher is PBKDF2-SHA256 unless configured otherwise.

The GopherMailForge specs were updated so mailbox-password and app-password/mail-client verifier storage must use Authentik-compatible Django encoded password-hash strings where password sync or Dovecot verification is intended. This rejects a private mail-only password hash scheme. The Dovecot passdb path must verify submitted secrets against the same stored verifier string. Imports and synchronization must reject plaintext, unknown algorithms, deprecated algorithms, or policy-disabled algorithms unless a documented migration exception exists.

This keeps Authentik adjacent rather than embedded: Authentik compatibility defines the verifier format, but Authentik outage must not become a runtime dependency for IMAP/SMTP authentication of already-stored verifiers.

Verification:

- Confirmed markdown links resolve.
- Confirmed `workflow.toml` parses.
- Confirmed `git diff --check HEAD~1..HEAD` passes.
- Fast-forwarded all six root worktrees to the commit.
