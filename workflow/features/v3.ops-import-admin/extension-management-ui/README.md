# Extensions administrator

State: `in_progress`

Host-owned GOTTH Mail administrator for extension inventory,
configuration, write-only secrets, permissions, health, enable/disable,
updates, audit, versions, and rollback.

It depends on admitted `gotth-extensions` consumer conformance. Extensions may
not inject presentation or receive Mail administrator authority.

The repository-local administrator is implemented and verified: durable
inventory, encrypted write-only secrets, actor/revision-bound previews,
host-owned API/UI, durable OIDC-role plus CSRF admission, runtime ordering,
update diffs, full-version rollback, and separate secret deletion/uninstall.

The production adapter is now implemented for the exact non-Telegram
`gotth.mail.notification.webhook` contract. It verifies a digest-named local
artifact, projects configuration and the HMAC key through owner-only files,
supervises the process group, authenticates a Unix gRPC transport, validates
the complete foundation handshake and health, admits/revokes alert routing,
and removes runtime secrets only after confirmed stop. Static notification
configuration conflicts fail startup rather than silently changing routing.

The bounded inventory renderer has a reviewed development checkpoint; see
[evidence/2026-09-27-renderer-inventory-admission.md](evidence/2026-09-27-renderer-inventory-admission.md).
The feature remains in progress: detail/terminal workflows, bounded projections,
cross-engine/floor, live-identity and full-image gates are not closed by that slice.

Earlier distribution evidence (not a current completion claim): canonical Forgejo
and public GitHub advertised the same annotated
`v1.0.0-alpha.1` tag object and the same peeled tested commit. Two independent
builds produced the same Linux/amd64 archive SHA-256. Release objects and
uploaded archive/checksum parity have not yet been proved, so production
install/enable remains closed until those exact public artifact identities are
published and pinned. Telegram is explicitly outside this resumed work.

## Approved pagination contract / implementation hold (2026-10-02)

State remains `in_progress`. Owner40028 approves HTML-only pagination and malformed
OFF-PAGE isolation; this is new behavior, not all-admin completion. PRD →
architecture → implementation specification were updated in that order before this
plan. None of these documents is execution evidence. Existing534-source pin-wrap,
normal/race/native/generator evidence remains attached to its pre-pagination scope.

Ordered atomic units; ONE active implementation subtree after parent contract review:

1. **Next atomic unit: service page selection, test-first.** Add focused real-SQL
   RED fixtures for keys-only51lookahead, selected full decode/status, complete
   traversal and preserved List behavior. Then implement only narrow
   ListInventoryPage with existing index,2+Pqueries and selected-key-loss error.
   No HTTP caller switch until this service boundary passes; no migrations/quotas.
2. **HTTP input and HTML navigation slice, test-first.** Add auth/query/status and
   full/HX/history/theme/empty/error component cases; integrate only inventory GET,
   page view and template, regenerate with existing pinned renderer. Preserve the
   JS eligibility rule: page links native; cursor-page refresh ordinary. No detail,
   terminal, API, serviceList or inventory.js policy change.
3. **Bounded acceptance/evidence.** Existing qualified PG16/17 and browser equipment;
   actual JS-disabled keyboard traversal and theme/current-page/Back/Forward,
   first-page HX nav freshness and cursor no-vendor/storage behavior. Fresh focused
   and applicable full/race/generation gates only after a revision-bound plan.
   Measure actual SQL work/bytes and shared request cost; projection50 is not a
   byte/grant/server-work bound. Keep all broader gates open.
4. **Independent cold review and parent admission.** Reconcile actual source,
   test populations, skips, cost and cleanup receipts. No feature completion,
   publication, deployment or another workstream without explicit authorization.

Dependencies:1→2→3→4; contract-review hold precedes1. No parallel source writer,
new equipment acquisition or support-framework work. Preserve2CPU/4GB/16GiBVM,
24GiBowner/128MiBfile/512MiBprivate tmp/077 and reserved collection time for future
runs; each later unit needs its own bounded authorization, not an automatic launch.
Rollback is code-only reversion of this isolated page entrypoint/HTML integration;
reverting to whole-list errors/cost is a visible policy reversal requiring review.

### Service unit checkpoint — verified, implementation review pending (2026-10-02)

The initial source gate failed on0644-versus0600 overlay expectations; its receipts
remain failures. Parent independently derived private modes from archive entries
and retained077 without changing permissions. Actual missing-method compile RED
then preceded ListInventoryPage implementation; it was not behavioral RED.

The new method and focused tests now pass on qualified PostgreSQL170010:49 focused
records,282 affected-package records,49 focused race records, zero failures/skips
or race diagnostics; vet passes. ListInventoryPage statement coverage is100%,
including synthetic defensive over-return and explicit-Close failures. This is
not universal behavioral coverage. The Unicode-domain fixture explicitly uses
UTF8/C.UTF-8; default C/SQL_ASCII fixtures remain unchanged. The earlier Unicode
fixture failure and all prior source/transport failures are retained.

Legacy List/Get/scanner/status/API/HTTP/templates/schema are unchanged. Live
inter-read deletion remains a driver-fixture simulation, not a live concurrency
proof. PG16, HTTP/native navigation and matched performance evidence remain open.
Independent implementation review is required before the HTTP unit. Native checks
closed14:51:29UTC, within the original14:55 deadline. State remains in_progress.

### HTTP pagination checkpoint — parent review pending (2026-10-02)

Unit2 now integrates authenticated cursor parsing, the admitted service page,
ordinary First/Next/theme/refresh links and genuine generated inventory output.
One atomic HTTP slice: parser/handler/view/template must agree before wiring the
new visible behavior. Service/List/scanner/status/API/detail/JS/schema remain frozen.
Behavioral RED37RUN (21FAIL/16PASS) preceded implementation. Final PG170010 checks:
focused38PASS, HTTP package276PASS+2existingSKIP, focused race38PASS, vet0 and
existing extension API19PASS. All three new helpers and the inventory handler's
29statements covered100%; this is not exhaustive branch/domain/browser proof.
Pinned generation write/write/check0 with equal outputs; detail outputs unchanged.
HTML request/link assertions are NOT native browser/JS-disabled/history evidence.
Actual target encoding/collation/stored-key compatibility remains UNATTESTED:
SQL_ASCII schema-legal keys need not satisfy approved UTF8 cursor grammar. No
stored-row filter/new failure policy/migration/quota was added to conceal this.
PG16, live concurrency, browser and matched performance/Amdahl remain later gates.
State remains in_progress. Hold next unit/publication/deployment for parent review.

## Permissions readability MVP — contract review hold (2026-10-03)

State remains in_progress. Owner40081 approves the smaller40080 slice: inventory
category counts + View permissions; ONE readonly detail pager with25 combined
entries, ordinary Previous/Next, no new JS. PERM-01..06 in PRD/architecture/spec are
written in that order before this plan. This supersedes no unrelated existing WIP.
Owner40075 provisionally accepts current performance tradeoffs; held1152 O/N/C
study stays stopped. Historical evidence remains separate, not retroactive proof.

ONE sole writer and active product slice. Current unit edits only these five docs;
no implementation/test/generated/native/remote/commit/deploy authority yet.

1. **Parent contract review first.** Review exact GET precedence/grammar/range/empty
   behavior, metadata-recovery exception and strict readonly/authority split. Detail
   recovery still withholds grants even when inventory shows counts; no alternate
   route is authorized. Stop on contradiction, not an invented expanded feature.
2. **Next implementation unit, tests first after authorization.** Add narrow helper/
   route/component tests from the spec, preserving source543 baseline and unrelated
   dirty work. Establish honest behavioral/compile RED as applicable. Implement only
   count/link presentation, small GET parser/window/URL projection and existing
   inventory/detail templ changes. Authority-bearing full forms/diffs remain intact.
3. **Generation and affected verification.** Existing pinned write/write/check,
   focused Go/affected normal/race/vet on qualified development/VM; practical100%
   helper statement coverage, explicit gaps. One existing browser fixture adaptation
   proves native keyboard/no-JS traversal/theme/history and complete forms/state.
   Reuse unaffected accepted tests only with source/dependency bridges. No blind
   full rerun, new collector, equipment acquisition or infrastructure repair chain.
4. **Independent final reviews, then parent admission.** Audit real source/diffs,
   generated identities, observations, exits, limitations and cumulative cost.
   No automatic next beta item, feature-complete marking, publish or deployment.

Finite checkpoints: contract unit<=15min and handoff before03:10UTC; next units only
after parent review. Overall2–3h target from02:52, target closeout05:45UTC with15min
reserve, NOT a guarantee or permission to overrun. Concrete blocker gets immediate
handoff. Performance review is display-proportionate; no benchmark campaign or
claim of whole-page/DB/memory boundedness. Full forms/diffs/backend work OUT OF MVP.

Before later native authority: actual time/footprint forecast counting all copies,
binaries, caches, proof and hops against provisional new-product256MiB cumulative
planning allowance. Retain old703138835B performance history, never reset it. Same
2CPU/4GB/16GiBVM,24GiBowner,128MiB/file,512MiBprivateTMP,077; current live allowance84%,
floor10%. No resource/access growth implied. Contract-only evidence lives in
.artifacts/gotth-mail-permissions-pagination-mvp-20261003/contracts; no runtime PASS.

### Permissions MVP implementation checkpoint — independent review pending

2026-10-03: parent admitted the five-doc contract; the single read-only vertical
slice is now implemented and scoped verification is GREEN. State remains
in_progress; this does not complete other UI/beta work. Native input checkpoint
03:49UTC preceded04:00; real browser04:04:34–04:04:40UTC passed. Final additional
HTTP assertions were test-only and rechecked on PG16/17/race; source-dependency
bridge preserves the prior native proof. No second browser or held benchmark run.

Evidence index: implementation/handoff.md under
.artifacts/gotth-mail-permissions-pagination-mvp-20261003. Review actual isolated
delta, retained RED/failures,316/314/2 package populations, final38PASS focused
families, coverage gaps, generated identities, native counts/closure and cumulative
capacity before admission. Next action is independent final review and parent
admission only; no automatic other beta item, commit, publication or deployment.


### Permissions MVP accepted — 2026-10-03 closeout

Both independent final reviews CLEAN; parent accepts PERM-01..06 without a fix.
The contract/implementation-review holds above are historical, superseded for this
MVP only. State remains in_progress. See [accepted evidence and named remaining
UI actions](evidence/2026-10-03-permissions-pagination.md). Existing verification
is reused against exact source identities; no new tests/native execution occurred.
Owner40075 provisionally accepts performance;40081 readability scope is delivered.
Next: finite historical dependency-region mapping and only identified uncovered UI
assertions on existing equipment; floor/live-identity/image/exact-target claims and
final whole-UI admission remain distinct. No automatic next beta or deployment.


### Normal-detail theme refresh — native GREEN, parent review pending

2026-10-03: exact page1 theme-selector fragment aligned in existing test driver.
Expected selector RED then one current-binary12-state320/1280 native GREEN; no
production/build change. See permissions-pagination evidence for source identities,
raw outcomes and limits. This is real focused coverage, not another mapping cycle.
Whole UI remains in_progress; external/floor/accessibility claims remain distinct.
