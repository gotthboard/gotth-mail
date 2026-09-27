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
A write error after committed200 cannot be converted to500. Existing unlimited
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
