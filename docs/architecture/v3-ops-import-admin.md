# Architecture — v3 Ops + Import + Mature Admin

Source PRD: [PRD-v3-ops-import-admin.md](../prd/PRD-v3-ops-import-admin.md)

## Goal

v3 adds operational maturity: audit UI, backup verification, snapshot/rollback guidance, Mailu import, abuse/rate-limit visibility, and mature admin workflows.

## Audit UI architecture

Audit capture exists from v0. v3 adds visibility:

- viewer
- filtering/search
- export
- retention tooling
- actor/resource/action filtering

Redaction remains enforced. UI must not expose secrets or unredacted before/after values.

## Backup/restore verification architecture

Backup verification flow:

1. capture backup through configured backup storage plugin
2. restore into temporary DB/container
3. run schema check
4. run daemon contract tests against restored data
5. mark backup verified only after validation passes
6. emit actionable failure report when any step fails

Storage mechanism is plugin-backed. Verification, failure reporting, and verified status are core-owned.

## Snapshot/rollback architecture

Snapshot UI shows:

- generated config
- migration version
- image versions
- plugin versions
- selected deployment policy
- verified restore status

Rollback UI provides guidance. It must not promise rollback for destructive migrations unless a verified backup exists.

## Mailu import architecture

Mailu import is the first import-source plugin.

Plugin responsibilities:

- parse Mailu source state
- report source items
- classify parse failures

Core responsibilities:

- validate imported state
- decide admission
- validate/adopt state into the canonical database
- write target state
- audit import mutations
- run contract verification

Supported imports where safe:

- domains
- users
- aliases
- relays
- DKIM keys
- compatible tokens

Import report includes:

- imported
- skipped
- incompatible
- manual action required

No import may silently weaken passwords, DKIM permissions, role mappings, or daemon lookup behavior.

## Abuse/rate-limit dashboard architecture

Dashboard surfaces:

- auth failures
- sender limits
- rejected recipients
- spam decisions
- suspicious outbound volume
- queue/deferred-mail correlation

It reads from existing logs/metrics/state; it must not invent hidden policy.

## Admin UI maturity

Adds:

- complete workflows
- config diff viewer
- mail flow trace UI
- permission simulator UI
- generated-config/plugin-backed status surfaces
- better diagnostics display
- bulk operations only with dry-run/preview, explicit confirmation, per-item result reporting, and per-item or grouped audit entries

Mature admin workflows call the same API/service/auth/audit paths as every other mutation surface. UI polish must not create a second mutation path.

## Extensions administrator architecture

The Extensions page is a GOTTH Mail control-plane view over a Mail-owned
registry. It is not a web surface served by extension processes.

```text
browser -> Mail admin routes -> authz/CSRF/confirmation
                              -> registry + encrypted secret store + audit
                              -> grant/routing/supervision adapter
                              -> authenticated out-of-process extension
```

The list and detail projections are secret-free. Constrained, versioned
configuration metadata is validated before Mail renders native templ
components. Unknown field kinds, duplicate names, over-limit documents,
executable presentation, arbitrary URLs/actions, and secret values fail
closed. Complex provider-specific workflows require reviewed Mail-owned
adapters rather than extension-injected UI.

Enable occurs only after the exact artifact, manifest digest, grant,
configuration revision, transport identity, handshake, and health result agree.
Disable first revokes the grant and removes the instance from new routing, then
stops it. Update is a separately confirmed privilege/configuration diff and
retains the previous pin. Every transition uses the existing service and audit
boundary and is idempotent or explicitly reconciled after ambiguity.

The page uses the separate administrator GUI's visual language and shares
reviewed design tokens with webmail, but it never gains webmail mailbox
authority. Mail and Board may present the same interaction pattern while
keeping separate registries and credentials.

The first production adapter is deliberately narrow. It admits only
`gotth.mail.notification.webhook` from
`https://github.com/gotthboard/gotth-extension-webhook`, with the exact
notification interface, capability set, configuration metadata, and HMAC-key
slot reviewed by Mail. This does not introduce Telegram behavior, arbitrary
extension execution, generic RPC, or extension-provided routing policy.

Deployment installs each verified immutable archive beneath a read-only
digest-named artifact root. Mail creates a fresh owner-only runtime directory,
writes separate configuration, binding, service-token, and secret files,
starts the pinned executable with paths rather than secret environment values,
and communicates over an owner-only Unix socket. A parent-death signal and
process-group termination prevent orphaned extension processes. Runtime files
are removed only after confirmed process exit.

### HTML inventory keyset boundary (2026-10-02; proposed, not implemented)

Only the HTML collection GET changes from Service.List to a narrow
ListInventoryPage entrypoint. Existing API GET internal/api/extensions.go:48,
service tests and cmd/gotth-mail/extensions_env_test.go retain List. No shared
pager, service-wide projection rewrite or mutation-path change.

Choose forward keyset pagination over deep OFFSET. Migration0017 declares
NOT NULL extension_id, length3..128 characters, CHECK product='gotth-mail', and
UNIQUE(product, extension_id); the resulting existing unique B-tree supports
product equality plus extension_id range/order. Its ordering uses the existing
column collation, including comparisons. The state index(enabled,lifecycle,
extension_id) is not the appropriate unconstrained inventory prefix. No new
index/migration is proposed. OFFSET would discard increasing prefix work and
shift positions under deletion. Adding an instance-ID tiebreaker for an impossible
within-product tie would add cursor/index complexity without solving a real case.
If uniqueness/collation changes later, this contract must be reviewed first.

Mechanism: query at most51 KEYS ONLY in ascending order, retain at most50 selected
keys, derive HasMore from the extra key. Close/check that result before fetching
full existing instanceColumns for exactly those selected keys, ordered identically.
Run existing scanInstance on each selected row, close/check rows, then existing
loadSecretStatus once per selected instance (even empty grants). Do not call List
then slice; do not select/decode51 complete rows or load sentinel status. No COUNT,
additional validation of decodable metadata, or omission of existing decode fields.
No secret values or metadata become inventory content.

This is deliberately two reads, not a new long-lived transaction/snapshot. A
selected key disappearing between selection and fetch fails the whole request
with the existing inventory500, without auto-retry/refill/partial page. Other
updates can be reflected by the second read or later status reads just as current
List has separate status snapshots. Next encodes the last selected key, not the
sentinel. Deleting that cursor key is harmless: the next predicate seeks strictly
after its value without requiring the row to exist. Inserts behind the cursor
require First; inserts ahead may appear on subsequent pages. Changing extension-ID
through out-of-band SQL can move/repeat/omit an instance during traversal; normal
service transitions do not rename it. No fictitious snapshot guarantee.

Successful SQL query counts:1 for zero keys;2+P for1..50selected instances, with
at most51 key rows +P complete instance rows +sum(current granted status rows).
Each key is at most512 UTF-8 bytes under the128-character schema constraint;
full JSON/config/metadata bytes and grant/status counts per selected row remain
unbounded by this change. Application materialization is O(key bytes+selected
payload bytes+selected grants+rendered bytes), not O(all installed payloads).
The outer render buffer and templ/driver allocations remain. Database work is
NOT capped at51 visits: keyset normally permits a B-tree seek/range walk, while
MVCC/dead tuples, planner choice, the selected-key ANY query/sort and each status
query can cost more. Measure plans/buffers and shared auth/render/status costs;
no global request-latency, detail/schema/grant or Amdahl closure is claimed.

UI: First/Next are ordinary full-document links inside the existing swapped
inventory region, so a canonical first-page HX refresh updates navigation as well
as rows. Keep inventory.js's four exact canonical URL eligibility rules and its
storage boundary UNCHANGED: cursor pages intentionally use ordinary refresh,
without loading HTMX or persisting cursor paths through the vendor. Theme and
refresh/reload links preserve the current cursor; detail/terminal links/forms stay
unchanged. Direct HX requests still honor existing fragment/history rules on any
valid selected page. No new enhanced page navigation or history implementation.

Rollback is the narrow HTML caller/navigation change back to List; no schema/data
migration or destructive reversal. This restores old all-row failure/cost behavior
and therefore requires an explicit product decision, not a silent fallback.

## Verification gates

- audit UI answers who changed what, when, through which path, and result
- backup verification restores into isolated environment, proves schema/contract validity, and reports actionable failures
- snapshot UI shows config/migration/image/plugin/deployment state
- Mailu import moves supported state without silent weakening
- abuse/rate-limit dashboard exposes useful signals
- admin workflows do not bypass API/service/auth/audit paths
- bulk operations prove preview, confirmation, per-item result reporting, and per-item or grouped audit entries
- extension metadata cannot inject presentation or authority
- setup/test/enable/disable/update/rollback preserve grant, routing, secret,
  audit, accessibility, and failure-isolation boundaries

### Metadata-independent recovery document

Classify the authenticated loaded detail snapshot before field projection or
metadata-dependent dispatch. An invalid snapshot uses a scalar-only recovery DTO
and dedicated component in extensions_detail.templ; normal detail components are
not called. Existing detail buffering/CSP/no-store, authorized route spelling,
CSRF lengths and themes remain. Allowed service calls retain all rechecks.
Reclassify returned state before fields: valid restoration returns normal detail;
uninstall returns the existing terminal receipt. Errors show sanitized notices and
last-observed/verify-current-state wording, not a rollback promise. No added Get.
This UI policy is not new atomic backend validation under concurrent corruption.

## Read-only Permissions MVP boundary (2026-10-03; contracts only)

Implements PERM-01..06 without a new service, route or permissions subsystem.
The existing inventory selection/read still loads complete instance data; render
three len-based category counts and one safe existing-detail#permissions link.
Do not inspect/sort/copy grant values merely to count them or introduce metadata
classification, additional service reads or per-row navigation in inventory.

Normal detail continues existing route/auth/nil/service.Get/metadata classification.
Only metadata-valid GET presentation interprets permissions_page. Recovery selection
precedes that parser and stays metadata-free; even a malformed paging parameter
must not unlock/replace recovery or alter its status/withheld actions. This deliberately
does NOT reject oversized paging queries before the existing Get/materialization.

Represent the visible window as up to three borrowed sub-slices of the loaded
capability/interface/secret-slot-name lists (or at most25 small labeled references).
A fixed-three-category offset walk selects at most25 entries without concatenating,
sorting or copying whole arrays. Keep full Item/preview/Fields authority objects
intact; the separate display window must never flow into update/configuration or
approval inputs. Recompute from the current loaded view, not a session snapshot.

GET navigation URLs are host-owned: existing escaped authorized detail-route
spelling, normalized theme, optional permissions_page, fixed #permissions anchor
for Previous/Next/View permissions. Detail theme navigation preserves page position
without changing its existing full-navigation behavior. Mutation ActionURL is a
separate unchanged builder: no page, fragment, Host, return URL or arbitrary query
propagation. POST uses its existing parser/auth/CSRF/actions and displays read-only
page1 on a normal result; it never invokes the new GET pager parser.

Inventory full/HX fragment/history rules and inventory.js/vendor/storage eligibility
remain unchanged. Detail remains full-document, script-none/no-store/buffered even
when HX headers are supplied. Native history has existing live/cache limitations;
no History API, storage, inline handlers, hx-boost or new enhancement is introduced.
Reuse scripts/generate-extension-inventory.sh's existing inventory/detail component
pairs and pinned tools; no new generator or hand-edited generated Go/CSS.

The local window-selection work is constant-category plus at most25 references;
rendered entry bytes, escaping and buffering remain variable. Full forms/diffs and
other sections, backend reads/decoding/status work and materialized arrays remain
outside this optimization. No global latency, HTML, SQL-work or allocation bound.
Rollback is the isolated display/parser/link change plus regenerated outputs; it
restores expanded read-only lists and their cost, without schema/data migration.
No rollback is executed or other existing WIP reverted by this contract unit.

### PERM implementation/evidence bridge (2026-10-03)

Implemented as three private functions in extensions_permissions_page.go plus a
safe inventory display-link helper. The controller admits the requested window
before rendering; the template recomputes that constant-three-category window so
direct component calls and normal POST results default to page1. Only a scalar page
number joins the view; full Item/Fields/Preview/UpdateTarget data stay intact.
Generated inventory/detail components use existing pairs; only inventory CSS bytes
changed. Service/API/DB/mutation routines, ActionURL, recovery components, production
JavaScript and vendor/storage policy are byte-identical to the admitted baseline.
Native evidence uses the existing pagination browser fixture/driver with a new
permissions-only mode, unchanged process/drain mechanisms and no new browser stack.
