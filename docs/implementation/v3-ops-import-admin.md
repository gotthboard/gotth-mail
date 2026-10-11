# Implementation Spec — v3 Ops + Import + Mature Admin

Source PRD: [PRD-v3-ops-import-admin.md](../prd/PRD-v3-ops-import-admin.md)
Source architecture: [architecture/v3-ops-import-admin.md](../architecture/v3-ops-import-admin.md)

## Goal

Add serious operator surfaces: audit UI/search/export, verified backup/restore, snapshot/rollback guidance, Mailu import plugin, abuse/rate-limit dashboard, and mature admin workflows.

## Audit UI/search/export

API:

```text
GET /api/v1/audit/events
GET /api/v1/audit/events/{id}
GET /api/v1/audit/export?format=jsonl|csv
```

Query filters:

- time range
- actor type/id
- action
- resource type/id
- result
- correlation ID
- error code

Export preserves redaction. UI must not expose secrets or unredacted before/after values.

Retention tooling:

```text
gotth-mailctl audit retention preview --policy <policy>
gotth-mailctl audit retention apply --policy <policy> --confirm <preview-id>
```

Retention apply is a mutation and must be audited.

## Backup/restore verification

Backup state table:

- `id`
- `plugin_registration_id`
- `status`: `captured`, `verify_running`, `verified`, `failed`
- `artifact_ref`
- `schema_version`
- `config_set_id`
- `created_at`
- `verified_at`
- `failure_report_json`

Flow:

1. capture backup through backup storage plugin
2. restore into isolated temporary DB/container
3. run schema check
4. run daemon contract tests against restored data
5. mark verified only after all validation passes
6. emit actionable failure report on any failure

Core owns verification, failure reporting, and verified status. Plugin owns storage mechanism only.

Failure report includes failed step, safe error, remediation hint, correlation ID, and whether retry may help.

## Snapshot/rollback UI

Snapshot API:

```text
GET /api/v1/snapshots
GET /api/v1/snapshots/{id}
GET /api/v1/snapshots/{id}/diff?against=<id>
```

Snapshot fields:

- generated config set ID/hash
- migration version
- image versions
- plugin versions
- deployment policy hash
- verified restore status

Rollback UI provides guidance. It must not present a destructive rollback as safe unless a verified backup exists.

## Mailu import plugin

Plugin seam: `import`.

Mailu import plugin responsibilities:

- parse Mailu source state
- classify source items
- report parse failures
- return candidate records

Core responsibilities:

- validate candidates
- decide admission
- validate/adopt state into canonical DB
- audit import mutations
- run daemon contract verification before declaring success

Import candidate types:

- domains
- users/mailboxes
- aliases
- relays
- DKIM keys
- compatible tokens where safe

Token/app-password import is allowed only for v2-supported Authentik/Django `pbkdf2_sha256` verifier, non-plaintext records whose hash/verifier algorithm, parameters, scope, and revocation state can be preserved. Anything else is `incompatible` or `manual_action_required`.

Live Mailu user-password import uses Mailu `config-export --secrets --json` data. Mailu Passlib `bcrypt-sha256` password hashes must be preserved as `mailu_bcrypt_sha256$<original-mailu-passlib-hash>` for Authentik custom-hasher migration compatibility. They must not be presented as Django `bcrypt_sha256`, and redacted non-secret exports are rejected for user password preservation. Applying an import may adopt those mailbox records for routing/recipient state, but local Dovecot secret verification remains limited to verifier algorithms implemented by GOTTH Mail.

Import report item status:

```text
imported
skipped
incompatible
manual_action_required
failed_validation
```

No import may silently weaken passwords, DKIM permissions, role mappings, or daemon lookup behavior.

API:

```text
POST /api/v1/imports/mailu/preview
POST /api/v1/imports/mailu/apply
GET  /api/v1/imports/{id}
```

Apply requires explicit confirmation using preview ID/hash, source fingerprint, actor binding, and expiry. Stale previews, changed source fingerprints, mismatched actors, or mismatched preview hashes are rejected.

## Abuse/rate-limit dashboard

Inputs:

- auth failure events
- sender limit events
- rejected recipient events
- spam decisions
- suspicious outbound volume metrics
- queue/deferred-mail correlation

Dashboard reads existing logs/metrics/state. It must not invent hidden policy.

API:

```text
GET /api/v1/ops/abuse-summary
GET /api/v1/ops/rate-limits
GET /api/v1/ops/deferred-correlation
```

## Mature admin workflows

Bulk operation pattern:

```text
preview -> explicit confirmation -> per-item execution -> per-item result report -> per-item or grouped audit entries
```

Bulk operation APIs include:

```text
POST /api/v1/bulk/<operation>/preview
POST /api/v1/bulk/<operation>/apply
GET  /api/v1/bulk/jobs/{id}
```

Apply must verify preview hash, actor, action, resource scope, and expiry. Stale previews are rejected.

UI polish must not create a second mutation path. GOTTH screens call API/service/auth/audit paths.

## Extensions administrator

Host-owned routes:

```text
GET  /admin/extensions
GET  /admin/extensions/{instance-id}
GET  /admin/extensions/{instance-id}/audit
POST /api/v1/extensions/{instance-id}/configure/preview
POST /api/v1/extensions/{instance-id}/configure/apply
POST /api/v1/extensions/{instance-id}/test
POST /api/v1/extensions/{instance-id}/enable
POST /api/v1/extensions/{instance-id}/disable
POST /api/v1/extensions/{instance-id}/update/preview
POST /api/v1/extensions/{instance-id}/update/apply
POST /api/v1/extensions/{instance-id}/rollback
POST /api/v1/extensions/{instance-id}/uninstall/preview
POST /api/v1/extensions/{instance-id}/uninstall/apply
```

### Inventory GET representation and build

The inventory GET is the bounded renderer migration slice. Detail, confirmation,
POST actions and audit download retain their existing implementation and authority;
this does not declare the wider renderer or extension feature complete.

Inventory uses escaped templ components, checked-in Tailwind utilities without
Preflight, shared scalar webmail colors and the same single embedded HTMX2.0.10
asset. Existing webmail asset URLs, bytes, MIME/security/cache headers and theme
behavior remain unchanged. The new exact public GET asset allowlist is
/admin/extensions/assets/{inventory.css,tokens.css,htmx-2.0.10.min.js,inventory.js};
assets contain no registry/identity/CSRF data and use no-store/nosniff.

List/authentication order and cookie/bearer precedence remain unchanged. Projected
fields are repository, actual artifact pin (not invented semantic version),
manifest/grant digests, capability/interface/secret-slot names, lifecycle, health,
enabled state, available update and rollback pin. Configuration, secret values,
session digests and metadata labels are not inventory content.

Only exact HX-Request:true without HX-History-Restore-Request:true selects the
fixed-marker fragment. Full, fragment and error responses set Vary for both
headers and Cache-Control: private, no-store before authentication. One outer
buffer prevents render failures committing partial200; errors return sanitized500.
A write error after committed200 cannot be converted to500. The existing pre-pagination unlimited
List retains its existing L bytes (including fields not displayed); the outer
render buffer adds O(B) bytes for rendered B. Renderer work scales with rows/bytes,
while auth/SQL costs remain delegated, including existing per-instance status
queries. This is not a fixed bound; the separate boundedness gap remains open.

Theme uses ordinary ?theme=system|light|dark links, normalizing unknown/absent to
system, with no new cookie/localStorage. Explicit modes override OS preference.
External scripts and styles obey default-src 'none', script/style/connect/img/font
'self', frame-ancestors/base-uri/object-src 'none', form-action 'self'; no inline
handlers, unsafe templ casts or extension presentation. Accent3px focus outlines,
underlined links and textual state preserve the reviewed contrast choices.

Refresh starts as an ordinary href. Companion handlers are installed before
operative hx attributes. The sole inventory.js loader waits for complete/window load,
fixed shell/meta and both same-origin stylesheets, then appends one immutable vendor
script with load/error handlers already registered. Exact actual-browser full URL
must equal location.origin plus /admin/extensions or precisely one of the three
?theme=system|light|dark queries. No parsing/normalizing unknown forms into eligibility.
Version/config/URL/prerequisites are rechecked before activation and requests. Missing/blocked script or
CSS keeps full-navigation fallback. HTMX evaluation, script tags, indicator-style
injection, History API/snapshot options and nested OOB swaps are disabled;
self requests only and a10-second timeout are enforced. Only exact200/HTML MIME/
fixed marker/expected target/completed swap announces success. Response HX command
headers are rejected before HTMX processes them. Every terminal failure settles
busy state:401/403 clear stale rows; other failures visibly mark retained content
stale and expose an ordinary reload link. Persisted pageshow clears content and
reloads; this mitigates BFCache staleness, not pre-event paint or no-script BFCache.

Generation is build-only: templ runtime/generator0.3.1020, Go1.26.6 and official
standalone Tailwind4.3.3 linux-x64/glibc. The isolated tools/renderer Go module owns
the generator-only dependency graph. tailwind-standalone.json pins publisher URL,
asset479118279, size111749248 and SHA256dc61b3ac6b8c9ca874c0cc4c57b2409791a64c5540404ca5f5367360babc313a;
tailwind-LICENSE preserves MIT. Publisher HTTPS/checksum provenance is not a binary
signature, attestation or source-rebuild guarantee; the tool embeds Bun/native code.

scripts/generate-extension-inventory.sh requires explicit GO_BIN, TAILWINDCSS_BIN,
private GOCACHE/GOMODCACHE and off-root TMPDIR. Existing bash/bwrap/jq/coreutils are
build equipment; Node/npm is not a generation/runtime dependency. Size/hash/platform
checks precede tool execution. Generation enforces local toolchain, no workspace/
ambient Go flags, normal checksums, GOPROXY=off and its own network/PID-denied,
read-only-source/private-write namespace. Missing inputs fail; no acquisition,
PATH fallback for Tailwind, installer or npm-policy change occurs. Source module
metadata is staged only for templ's runtime-version check, not merged tool MVS.

Use --write to regenerate the one inventory templ source and explicit-source(none)
theme/utilities CSS, or --check to reject stale checked-in Go/CSS without rewriting
it. Two clean output generations must match. Production builds embed those outputs;
no compiler, Bun or Node is launched for this renderer at application startup.
The production-image builder requires --check after existing argument/HEAD/epoch/
source-state/clean-tree guards and before Docker discovery. No skip/download or
source rewrite is allowed. Stubbed sequencing tests do not prove actual generation
or full images; those are separate gates.

Inventory browser mode reuses the existing admitted alpha.1/private-PG16 fixture:
exactly five runner arguments, fixed new driver, native keyboard/theme/refresh,
no bearer/non-GET/receiver/runtime activity or measured SQL changes. Login remains
injected. Chromium151 evidence does not close Chrome111/Firefox128/Safari16.4 or
live-identity gates. Fault injection is explicitly transport evidence; handler
contracts separately cover real authentication, SQL and rendering failures.

Reviewed storage boundary: HTMX may persist htmx-current-path-for-history with only
one of the four exact public path/query literals above. Its fixed temporary
htmx:sessionStorageTest probe (same literal value) is synchronously removed after
a successful availability check; a preexisting colliding probe is overwritten/removed.
Canonical loads overwrite the vendor current-path slot, not unrelated sentinels or
HTML history caches. No localStorage changes, arbitrary query/credential/HTML state,
History API rewrite, vendor patch or storage-API override is admitted. Unknown,
duplicate, encoded, bare-query, userinfo or hash URLs retain authorized ordinary
HTML, no vendor request/evaluation and byte-identical preexisting storage maps.
Persisted-pageshow protection remains installed on URL-rejected fallback. This
controlled document has no other URL-mutating scripts; arbitrary hostile same-origin
scripts and other pages on the origin are not certified by this boundary.
Native canary red then repaired green, four canonical refreshes, sentinel/event
oracles and explicitly injected ordering/storage-denial cases are recorded in
workflow/features/v3.ops-import-admin/extension-management-ui/evidence/2026-09-27-renderer-inventory.md.
Parent/cold review, cross-engine/floor and feature/beta admission remain separate.

### Planned HTML inventory pagination (owner40028; contracts only)

This subsection supersedes only the all-row HTML selection requirement above
when implemented and reviewed. Existing implementation/evidence is not silently
rewritten as pagination evidence. PRD and architecture define the approved scope.

#### HTTP input and observable errors

Preserve order: inventoryHeaders; exact route/GET guard404; existing bearer/cookie
actor authorization401/403; service-nil503; THEN bounded page parsing, service,
view and buffered rendering. Do not expose cursor-validation results before auth.

- Fixed page size50, not user configurable and not an installed-instance quota.
  Only one new reserved query field: after. Absent means first page. Explicit
  empty or repeated decoded after keys (including encoded aliases) are400.
- After the existing admission checks, reject RawQuery over4096bytes with
  sanitized400 before allocating parsed query values. Use error-returning
  url.ParseQuery; malformed escaping/invalid separators return400 rather than
  silently retaining a partially parsed query. This is an intentional new input
  error boundary. Unknown query keys within that bound remain ignored, as before.
- after format is v1. followed by canonical unpadded base64url of the last selected
  extension_id's UTF-8 bytes. Max encoded value686bytes (3+ceil(512*4/3)); reject
  other versions, padding/noncanonical spelling, invalid UTF-8, NUL, decoded
  length outside3..128characters or over512bytes. Re-encode to check canonicality.
  Percent-encoded query spellings are parsed normally, but do not broaden browser
  enhancement eligibility. The cursor is a position, not authority or a signature.
- A well-formed nonexistent/deleted/beyond-end key is a valid seek, not404 or a
  redirect: it returns the following page or an empty200. No page number/offset,
  max-page quota, total count, global config or arbitrary return URL is added.
- Preserve existing theme semantics: first decoded theme value; light/dark
  explicit, absent/other normalized to system. Duplicate theme retains that
  existing first-value behavior; only duplicate after is rejected. Generated
  links use the fixed /admin/extensions path and encoded host-owned query values.
- Bad pagination input uses a fixed non-reflective400 message. Selected read,
  key-disappearance, scan/decode/status and key/full-result Close failures use500
  'extension inventory unavailable'. Rendering failures retain their separate
  existing sanitized500; post-commit transport errors cannot become500. Existing
  CSP/no-store/Vary headers apply to errors too. No partial rows or error-to-empty.

#### Narrow service and SQL contract

Introduce ListInventoryPage(ctx, afterKey) returning Items and HasMore, with50 a
private projection constant. Empty afterKey means first; validate nonempty key
shape defensively before SQL. Do not change List, Get, scanInstance, status-query
semantics, API callsites or their existing tests to satisfy paging. A next cursor
is derived by the HTML layer from the last selected Item.ExtensionID only when
HasMore; service accepts decoded key values, never raw URLs/SQL fragments.

1. First-page static SQL selects extension_id FROM extension_instances WHERE
   product=$1 ORDER BY extension_id LIMIT51. Subsequent static SQL adds
   extension_id>$2 with the SAME column collation/order. Values are parameters;
   neither cursor nor sort text is SQL source. Scan at most51scalar keys, checking
   rows.Err and Close before any further query. The51st is existence evidence
   only: never scanInstance/Get/status it. Save the first50 and HasMore.
2. If no selected keys, return an empty page after that one successful query.
   Otherwise select the COMPLETE existing instanceColumns WHERE product=$1 AND
   extension_id=ANY($2::text[]) ORDER BY extension_id, binding only selected keys.
   At most50full rows can match the existing unique key. Use current scanInstance,
   including both metadata passes and configuration decode; no selected-column
   pruning. Check full selected-key membership/count, rows.Err and Close. A key
   removed between the two reads fails500 rather than silently dropping/refilling.
3. Only after complete selected-row decode/close, call current loadSecretStatus
   once for every selected instance, including empty SecretSlots. Preserve current
   granted-slot filtering and errors; never query/decode lookahead grants/status.
   On any returned error, return no usable page. Status helper deferred-Close
   behavior is unchanged; do not claim newly checked status Close errors.
   No new transaction, retry or mutation.

Read consistency: the key probe, payload read and per-instance status reads can
observe different committed states. Replacement at the same extension key may
show its replacement instance; concurrent payload/status changes remain live
observations. A removed sentinel can yield a subsequent empty page. A newly
inserted row before the cursor is not retroactively included; First restarts.
Future extension-ID renames or out-of-band changes can repeat/omit instances;
no snapshot claim. Stable constrained datasets remain exhaustively reachable.

Query budget is1(empty) or2+P (P<=50), excluding unchanged auth/runtime-observation
work; key/result/close errors stop earlier. No COUNT query, sentinel payload,
full-List materialization, new status aggregation, index or migration. Existing
UNIQUE(product,extension_id) is the ordering guarantee: duplicate same-product
IDs must be tested as existing SQL rejection, not fabricated supported ties.
Supported collation and schema constraints must stay intact. Keyset avoids OFFSET
prefix discards; it does not force the planner or bound all server tuple visits.

#### HTML, fragments and history

Place a labeled Inventory pages nav INSIDE inventoryRows/#extension-inventory,
with ordinary First page (when after exists) and Next page (only HasMore) anchors.
No Previous lookup or page count; browser Back/Forward and First provide return
navigation. Omit unavailable anchors or use plain explanatory text, never fake
hrefs/disabled clickable controls. Preserve native focus/underlining/contrast,
landmarks and document reading order; no autofocus on native page navigation.
State 'Up to50 entries per page' rather than inventing totals/page numbers.

- First/theme/Next URLs preserve normalized theme; theme and refresh/reload URLs
  preserve the current after cursor. First removes it. The inventory breadcrumb
  returns to First with current theme. Detail links and detail/terminal return
  behavior remain as currently implemented; no returnURL propagation.
- Empty first page keeps 'No extensions installed.' Empty cursor page instead
  says no entries after this position and offers First; never implies global
  emptiness. End pages expose no Next. A selected bad row yields whole-page error,
  not an isolated card or an unreachable record silently omitted from traversal.
- Exact HX-Request:true without exact HX-History-Restore-Request:true still returns
  the existing marker-prefixed inventoryRows, NOW INCLUDING navigation. History
  restoration still returns a complete document, for first and cursor pages.
  Full documents contain one region/nav; fragments never duplicate the shell.
- Leave inventory.js and HTMX config/storage eligibility unchanged. Only the four
  existing literal first-page URLs may enhance Refresh; cursor URLs intentionally
  do not load the vendor and use ordinary full navigation/refresh. Direct valid
  cursor HX callers still get correct fragments. A first-page enhanced refresh
  swaps rows+nav together, so Next availability cannot remain stale outside the
  region. Existing failed-refresh/stale/401-403-clearing/marker gates stay intact.
- All page links remain native even when HTMX is available. No pushState,
  hx-boost, OOB swap, localStorage, cursor-bearing vendor history slot or new
  response-HX command. Existing BFCache mitigation and its pre-paint/no-script
  limitations remain honest. Normal browser Back may show cached history; refresh
  reauthenticates/reselects and is not a frozen dataset guarantee.

#### Test-first and cost evidence (NOT RUN in this contract unit)

Service SQL fixtures on existing qualified PG16/17:0/1/49/50/51/100/101instances;
first/middle/end/stale/nonexistent key and complete traversal with exact ID sets.
Exercise maximum-length/multibyte legal keys and current collation; existing
same-product duplicate insertion must fail. Prove more-lookahead at exact50/51.
Put wrong-shape metadata/configuration/array payloads and current-slot infinity
status at selected versus51st/later positions: off-page data must not be fetched,
decoded or status-loaded; selected failures retain500/no page. Preserve semantics
for decodable unknown metadata kinds (no new ValidateMetadata policy). Exercise
empty-grant query errors, scan/rows/key-and-payload-Close/cancellation errors and deterministic
key deletion between selection/fetch without sleeps or automatic retry. Compare
legacy List/API behavior, including their all-row failures; no caller migration.

HTTP/component fixtures: auth-before-parse and service-nil precedence; duplicate,
empty, malformed, oversized, unknown-version/noncanonical cursor; raw-query cap;
theme/unknown-key compatibility. Full/HX/exact-header/history-restore/marker,
no partial200, empty versus stale text and native First/Next/current-page URLs.
Existing renderer generation/check after actual template work, never hand-edit
outputs. Browser later: JS-off keyboard complete traversal/Back/Forward/refresh,
theme on middle pages, selected failure, first-page HX refreshed Next availability,
cursor-page no vendor/storage activity, and default CSS/fallback behavior.

Performance evidence later uses the admitted equipment/limits, not a new benchmark
framework: explain/analyze/buffers on actual PG16/17 key and selected-key queries,
with growing N and first/deep cursors; record plans, returned/visited rows, loops,
heap/index reads and sort work. Compare legacy versus page query count, transferred
key/payload/status rows and bytes, allocations and request timings with matched
fixtures. Separate selected bytes/grants from total N and shared auth/status/render
cost.50 bounds instance count only; unbounded per-instance bytes/grants, detail
work and whole-request/Amdahl gates remain OPEN. A sequential plan is evidence to
review, not permission for an unapproved index/quota or a false DB-work bound.

### Remaining detail and mutation contract

The required HTML target remains server-rendered Go + templ + Tailwind with HTMX
fragments and ordinary form fallback; the legacy detail transition is still open.
Update preview and confirmation use separate native
forms: the confirmation form displays the accepted target artifact, manifest,
grant and session, and submits only its preview ID, CSRF, action and required
confirmation. Empty fields in the independent preview-input form cannot block
confirmation. Submitted target fields never replace the server-stored preview.
Every POST requires administrator authorization,
CSRF, bounded input, and the same service-layer confirmation/audit contract as
the API. Sensitive reconfiguration, capability expansion, rollback, uninstall,
and secret deletion require recent reauthentication or the product's admitted
equivalent high-risk confirmation.

The registry stores instance ID, extension/repository identity, immutable
artifact and rollback pins, manifest/configuration/grant/session digests,
lifecycle and health codes, enabled state, timestamps, and audit correlation.
Secret values live only in a Mail-owned encrypted installation secret store
that this feature must define and verify before the first extension can be
enabled; projections contain slot IDs and configured/rotated status only.
Secret-status reads select the loaded instance ID and its current granted slot
IDs in SQL, retaining slot ordering and issuing the query even for empty grants.
Returned status follows grant order; absent slots remain unconfigured. Retired
rows remain stored for rollback and still block uninstall until confirmed
all-secret deletion. This narrows transferred/materialized rows, not the number
of instances, grants, per-instance queries, or database scan work. Encoding the
text-array parameter adds work and storage proportional to grant bytes; the
status map contains matching current slots rather than all retained slots.
SQL-valid retired infinity timestamps, which production does not write, are
now excluded from time.Time scanning; a current-slot infinity still errors.
An arbitrary internal argument containing NUL may fail text-array parsing;
this is not a claim that PostgreSQL jsonb can persist a NUL-bearing grant.
A metadata secret field uses its exact field name as its granted slot ID; there
is no separate alias mapping. A required secret field keeps its native required
constraint until that slot is configured; optional fields remain optional.
Once configured, blank input retains the secret for configuration-only
preview/apply without changing ciphertext or rotation
time. This is presentation, not authority: an explicitly previewed new secret
still requires identical re-entry on apply under the existing secret binding,
confirmation and CSRF checks. Missing required initial secrets may be staged
but cannot pass readiness or enable.

Successful configuration preview retains the submitted non-secret scalar
controls for ordinary Apply without re-entry; it does not reload stored values.
Enum options reflect the selected value, including an explicit empty choice
where omission is valid. Metadata defaults permit missing required values but
are not inserted by ValidateConfiguration or this projection: omitted string,
integer and enum fields remain omitted, including fields with defaults. The
native checkbox adapter always supplies a boolean (unchecked means false).
Native required constraints follow that contract; secret constraints remain
write-only and status-dependent as above. Apply still verifies the exact
preview-bound payload, actor, revision, confirmation and secret re-entry.
Preview and Apply use sibling native forms: ordinary edits belong to Preview
and are validated independently of the blank Apply confirmation. Apply shows
the reviewed non-secret configuration and submits its own accepted controls;
unchecked booleans remain absent, checked booleans remain present, and blank
optional/default-backed scalars remain blank. Editing Preview does not change
the reviewed Apply target. Secret re-entry is a separate blank password input,
never a hidden or reflected value. Creating another preview does not consume
prior previews; existing revision, expiry and single-use checks still govern
which preview can apply.

The extension Audit link is a dedicated read-only browser download for an
installed Mail instance. It uses the existing bound identity cookie and paired
CSRF-cookie binding, then ops:admin authorization on that exact extension;
explicit Authorization still takes precedence. GET needs no submitted form
token. The UUID is canonicalized to lowercase before resource authorization.
The existing Mail registry must contain the instance before audit is queried.
No query overrides are accepted. The fixed resource type/id filter is applied
by SQL before the existing newest-first limit of 1,000 events. The page labels
this recent export, not complete history; uninstalled history remains available
through the unchanged bearer API, not this installed-only route.

Success is NDJSON with static attachment filename extension-audit.jsonl,
no-store and nosniff; zero events gives empty 200. Conditional headers do not
bypass authentication or produce 304. Exact-route non-GET methods return 405
with Allow: GET; invalid/missing installed IDs return 404, authenticated query
overrides 400, unavailable service 503, and registry/audit failures sanitized
500. Existing authentication/authorization failures remain 401/403. Route-local
errors retain no-store/nosniff and do not carry attachment disposition.
The existing reader and recursive redactor/JSONL exporter materialize rows and
bytes; the 1,000-row limit is not a byte/memory bound or a database-work bound.
No new export-byte cap, pagination, redaction policy or general API cookie
fallback is introduced. A concurrent uninstall after the read-only registry
check may still yield the already-authorized audit snapshot.

Configuration metadata admits only a closed set of bounded scalar field kinds,
labels, validation constraints, defaults, and named secret slots. It admits no
markup, script, style, template, executable expression, redirect, arbitrary
action, or secret value. Provider-specific complexity is implemented by a
reviewed Mail adapter.

Enable ordering is validate pin and metadata, persist configuration, inject
scoped secrets, authenticate transport, negotiate grant, start, handshake,
health, then admit routing. Disable ordering is revoke grant, remove routing,
stop, then record final state. Retried and ambiguous operations reconcile by
the bound configuration/session identities rather than guessing success.

With a fresh empty supervisor, startup transactionally invalidates historical
routing observations for enabled instances and audits each changed observation.
It preserves enabled intent, configuration/test revision, pins, grants and secrets,
but projects unrouted/degraded with `extension.restart-required` until an
explicit authorized Enable revalidates Start, authenticated Probe and routing
admission. Startup does not approve new grants or automatically launch an
extension. Reconciliation/audit failure fails startup rather than serving stale
ready state. Disabled instances remain disabled. Repeated Enable never treats
persisted enabled/routed flags as proof; current tested revision and scoped
secrets remain mandatory. A failed Enable revokes any previous route before
stopping, and propagates cleanup errors; persisted state can remain ambiguous
on audit failure and must not be treated as live runtime evidence. Test, Enable
and Disable are serialized by the single administrator service; no multi-process
controller guarantee is introduced. Failed Disable SQL/audit leaves the process
stopped and route revoked rather than launching an unaudited replacement;
retry Disable to record that state or explicitly Enable to recover. The native
HTML Recover / revalidate button uses that same enable action, with the existing
administrator role and CSRF checks and ordinary no-JavaScript POST; Disable
remains available. Observational health checks authenticate and report health
but never clear or grant lifecycle admission readiness. A failed explicit Probe
still invalidates readiness before another admission can succeed.

A valid protected runtime root containing unowned leftovers quarantines only
the managed extension mechanism. Mail HTTP, administrator inventory and Postfix
listeners remain available; historical enabled/routed instances become audited
unrouted/degraded with `extension.runtime-blocked` and retain enabled intent.
No leftover process, directory, socket or secret is adopted, deleted or signalled.
The administrator receives an actionable blocker: verify prior processes stopped,
clean only exact protected leftovers, then restart Mail and explicitly recover.
Unknown-state quarantine is latched; deleting files alone never unblocks it.
Invalid root ownership, permissions, symlinks or conflicting configuration still
fail closed. A nonblocking directory flock serializes cooperating supervisors'
root inspection and process-directory publication; local lifecycle locking keeps
Start/Stop/root observations coherent. This is not a multi-controller protocol
or protection against a malicious process with Mail's own filesystem authority.

Production runtime is enabled only when all three protected settings exist:

```text
GOTTH_MAIL_EXTENSION_MASTER_KEY_FILE
GOTTH_MAIL_EXTENSION_ARTIFACT_ROOT
GOTTH_MAIL_EXTENSION_RUNTIME_ROOT
```

The artifact root contains one directory per lowercase `sha256:<hex>` pin,
named by the hex portion. Each directory contains an immutable
`gotth-extension-webhook` executable and an `artifact-pin` file containing the
exact full pin. Directories and executables may not be symlinks or
group/world-writable. The runtime root is an owner-only non-symlink directory.

For every start Mail writes mode-0600 configuration, runtime-binding,
service-token, and `webhook.hmac-key` files below a new mode-0700 instance
directory. The child receives only those paths and the Unix-socket path in a
bounded environment. Mail verifies challenge echo, extension identity,
release version, control/interface versions, manifest/grant/session digests,
capabilities, and health before routing. Stop failure leaves the runtime record
and protected directory intact for reconciliation; it never reports success
while a process may remain alive.

The managed webhook route and a statically configured notification plugin are
mutually exclusive. Startup rejects that ambiguous configuration instead of
silently changing which backend receives alerts. The webhook adapter supports
alerts only; prompts and Telegram command/approval behavior are absent.

## Verification

Required tests:

- audit UI answers who changed what, when, through which path, and result
- audit filters and exports preserve redaction
- retention preview/apply requires confirmation and audit
- backup restore into isolated DB/container proves schema and daemon contract validity
- backup failure reports are actionable
- snapshot UI shows config/migration/image/plugin/deployment/verified-restore state
- rollback UI refuses fake safety claims without verified backup
- Mailu import preview/apply moves supported state without silent weakening
- import apply requires preview hash/source fingerprint/actor binding/expiry confirmation and audits mutations
- abuse/rate-limit dashboard exposes required operational signals without hidden policy
- admin workflows do not bypass API/service/auth/audit paths
- bulk operations prove preview, confirmation, per-item result reporting, and per-item or grouped audit entries
- list/detail projections are complete, bounded, and secret-free
- hostile configuration metadata cannot inject HTML/script/style/actions or
  broaden grants
- write-only secret create/rotate/delete never redisplays or logs values
- setup and test cannot enable an unhealthy or unauthenticated instance
- disable blocks new routing before shutdown and is safe to retry
- update previews bind actor, artifact, manifest, grant, configuration, expiry,
  and privilege diff; stale or changed previews fail closed
- prior pin rollback works without changing unrelated extensions
- keyboard, focus, status announcement, 320-pixel reflow, theme contrast, and
  ordinary HTML/no-JavaScript flows pass
- Mail cannot enumerate or mutate another product's registry or secrets
- `git diff --check`
- `go test ./...`

### Recovery-only detail exception (2026-10-01)

Use UI-only integer-default float64 finite/integral [-2^63,2^63) classification
before ValidateMetadata. Preserve legacy integral1.0/1e0/null and exact int64
defaults; do not change global decoding, configuration values or service writes.
ValidateMetadata cannot restore raw unknown/duplicate keys or predecode bounds.
Keep invalid metadata out of Fields, including operation errors and post-action
projection. Dispatch only Disable, secretdelete preview/apply, uninstall
preview/apply, rollback and outstanding update Apply. Withheld POSTs return200
with a fixed unavailable alert and no service dispatch. Auth/decode/missing
statuses remain unchanged; valid configure-preview retains submitted Fields.
The dedicated scalar DTO excludes metadata/configuration/diffs/secret lists;
identity/pin/preview checks derive existing contracts, never truncate authority.
Preserve authenticated CSRF lengths; do not reject raw lifecycle to block recovery.
Generate the existing detail pair using pinned tools/renderer templ0.3.1020;
no new generator pair or CSS change. Validation maps/marshal, copies and buffering
add real unadmitted cost. Native/CSS/performance and cold-review gates stay open.

## PERM-01..06: read-only combined Permissions pager (2026-10-03)

Contract-only addition supersedes the earlier expanded permission-name inventory
projection and normal read-only detail joins when implemented. All other existing
contracts/evidence remain scoped to their actual source; this does not certify the
broader historical requirement for bounded complete detail documents.

### Selection and exact GET contract

1. Preserve current detail headers, path/method guard404, bearer/cookie precedence,
   actor401/403, nil-service503, then existing service.Get and its missing/decode/
   status errors. Classify loaded metadata using the current rule. Invalid metadata
   still renders the same recovery-only document BEFORE new paging validation;
   no normal Permissions view, counts/list exposure or new recovery route is added.
2. Only a metadata-valid normal GET enters the new parser. Reject RawQuery longer
   than4096 bytes before url.ParseQuery allocation. Use error-returning ParseQuery;
   malformed percent escapes/separators give fixed non-reflective400. Within that
   bound, unrelated keys remain ignored. Existing theme uses first decoded value:
   light/dark explicit; absent/unknown becomes system; duplicate theme unchanged.
3. Reserve only permissions_page: absent means1; decoded duplicate keys (including
   encoded aliases), explicit empty, sign, whitespace, exponent, non-ASCII digits,
   zero or leading zero are400. Grammar [1-9][0-9]{0,18}; numeric value must fit
   positive signed64-bit, otherwise400. Decode percent encoding normally before
   validation. No extra installed-grant quota or configurable page size.
4. Obtain category counts from the COMPLETE loaded slices. Check each addition
   against platform max-int; impossible total overflow fails sanitized500, never
   wraps or silently caps entries. For total N>0, pages=1+(N-1)/25; N=0 has pages=1.
   Compare parsed page against pages BEFORE narrowing to int or multiplying.
   A valid numeric page>pages returns fixed404 'permissions page not found', without
   redirect, clamping or rendering another page. Get/not-found/read/recovery errors
   therefore still outrank invalid page input. Ordinary pager400 text is fixed
   'invalid permissions page query'; existing privacy/CSP headers apply to errors.
5. Only after page admission compute offset=(page-1)*25, then take=min(25,N-offset).
   Use remaining counts/subtraction to intersect three lists; never offset+25 or
   N+24 unchecked. Category order: capabilities, interfaces, granted secret-slot
   names. Preserve each list's order, duplicate occurrences and values; do not
   sort, concatenate, deduplicate, filter empty values or mutate the source slices.
   Render category labels (labeled groups suffice), at most25 entries combined,
   current page/total pages and explicit empty 'No granted permissions.' on page1.
   Unavailable Previous/Next are omitted, not fake/disabled clickable anchors.

Every stable valid grant set is reachable through ordinary native Previous/Next;
this is an index into the current loaded lists, not authority or a snapshot token.
Concurrent changes can move entries or make a previously valid page404; browser
Back may show cached content. Restart at page1/current detail to traverse new state.
No frozen traversal guarantee, silent refill or automatic retry is added.

### URLs, presentation and immutable mutation authority

Inventory displays all three counts including0 plus View permissions. Use existing
safe detail-ID admission/fallback, normalized current inventory theme and fixed
#permissions; no raw Host/query or unsafe templ cast. Do not add inventory metadata
validation to hide counts or invent another recovery route. For invalid metadata,
that existing detail destination remains recovery-only, even with #permissions.
Other inventory fields/navigation and full/HX/history/marker behavior stay intact.

Detail pager links use the already-authorized route spelling (not a canonicalized
replacement Item ID), escaped as existing action URLs; encode query values. Page1
links omit permissions_page; later pages include one canonical decimal value. Keep
normalized theme and append #permissions to pager anchors. Normal detail theme
links preserve current page; their existing native navigation/preview-loss notice
remains. No new JavaScript, endpoint, HTMX response/header, storage or vendor policy.

**Never replace or slice view.Item.Capabilities/Interfaces/SecretSlots.** The full
update-preview inputs at extensions_detail.templ:139-141 and complete approval
PrivilegeDiff/ConfigurationDiff/SecretSlotDiff at155-157 stay unchanged, as do
UpdateTarget, Fields, CSRF, preview IDs, confirmation and all secret/recovery forms.
Only the readonly joins at291 and inventory list loops become the display projection.
Line references name the pre-MVP543 baseline, not generated-line guarantees.

New paging parsing is GET-only. Existing POST ParseForm/body limits/errors remain
(including its existing malformed-query behavior); pagination cannot affect action
selection, target identity, preview binding, confirmation, redirects or terminal
receipts. Existing ActionURL stays detail path+theme ONLY, no page/fragment; normal
POST responses select display page1 without new request-parameter errors after a
mutation. Theme navigation still discards displayed previews and reloads stored
state as documented. Recovery/terminal documents and all withheld surfaces unchanged.

### Finite implementation verification (not run in this unit)

Tests first: empty/25/26/several pages; category boundaries at24/25/26; empty middle
category, duplicates and escaping; flatten traversed labeled entries and compare
exactly once with concatenated ORIGINAL fixture lists. This test oracle may join
lists; production render selection must not copy/sort them all. Exercise first/last
omitted links, malformed/duplicate/encoded/4096/4097/19-digit/overflow input, valid
beyond-end404, empty page1/page2, auth/nil/Get-error/recovery precedence and themes.

Check complete update-form values and ALL complete approval diffs with >25 entries
across page changes and POST success/error; preserve existing action URL, CSRF,
actor/target/revision/expiry/confirmation, secret/redaction and recovery tests.
Assert detail HX requests still full documents and inventory full/fragment counts/
links agree without broadening vendor/storage eligibility. Add source-bound normal
and focused race/vet checks for affected packages; reuse unchanged accepted proof
with explicit dependency/identity bridges, not blanket fresh-suite claims.

Regenerate ONLY with existing generate-extension-inventory.sh --write/--write/--check
and pinned equipment, proving identical two writes. No generated-file hand editing
or second renderer pair. Adapt ONE existing native browser fixture mode for actual
keyboard/no-JS View permissions/Next/Previous/theme/Back/Forward and full-form/state
oracles. Use existing qualified development/VM, no acquisition or production DB.
Aim100% changed-helper statement coverage where practical; name real gaps rather
than claim exhaustive behavior. Performance review is proportional display/source
cost review and available focused observations, not a benchmark campaign or an
unverified faster claim. Full forms, status lists and backend materialization remain
unbounded by this MVP; missing performance measurements are not newly passed.

### PERM scoped verification checkpoint (2026-10-03; uncommitted)

Helper missing-symbol compile RED preceded helper34PASS. Corrected routed/component
behavioral RED37RUN/35PASS/2FAIL preceded UI implementation; UI GREEN37PASS followed
actual pinned write/write/check with equal generated identities. Affected HTTPUI
normal tests pass on PG160014 and170010:316RUN/314PASS/2existingSKIP each. Skips are
TestInventoryGeneratorContract (separate genuine generation performed) and
TestInventoryRenderResourceSamples (no performance campaign). Vet passes.
Final strengthened focused PG16/PG17/race checks each38PASS; no skips/race diagnostics.
Parser and both URL helpers have100% statement coverage; window95.8% excludes its
unconstructible safe-slice total-overflow guard, not covered with unsafe forged
headers. Generated permission component70% includes unexercised generated error
paths; no exhaustive behavioral/coverage claim.

Tests retain full arrays through GET pages and real POST preview/error paths;
exact complete capability55-entry and secret-slot56-entry diffs are checked.
All three30-entry diff arrays are checked at component level, including error-view
flags. Existing HTTP update-preview keeps metadata unchanged, so schema diff is
empty. Existing service PrivilegeDiff describes capabilities only, not interfaces;
interface form/target behavior is unchanged, not newly advertised as interface-
diff coverage. The later assertion corrections changed tests only, not backend policy.

One actual Chromium153/PG16 workflow passed with scripts disabled: three26-count
inventory labels, View permissions,25/25/25/3 entries, native Tab/Enter and page/theme
navigation, native history Back/Forward (CDP history entry, not keyboard shortcut),
full update inputs and blank password fields. It observed9 authenticated document
GETs+1unauthenticated401;0POST/bearer/SQL/runtime/receiver changes during its readonly
interval. Login and grant setup are synthetic; no live identity/cross-engine/CSS-off
or whole-accessibility claim. Browser/HTTP drained; standard testpg ignored-close/
Wait limitations remain, even though namespace and external census were empty.

All failed attempts remain in the ignored implementation packet: test-double compile
mistake, an admitted stage with no selected command (its zero exit is NOT PASS),
pre-existing projection expectations and test-oracle assumptions. Corrections used
new stage IDs. Later changes only strengthened HTTP *_test.go assertions, which are
not linked into the cmd browser binary; immutable production/generated/driver hashes
bridge the successful native proof, without a second browser or blind full rerun.
Evidence: .artifacts/gotth-mail-permissions-pagination-mvp-20261003/implementation.
Independent reviews and parent admission still required; no commit or deployment.
