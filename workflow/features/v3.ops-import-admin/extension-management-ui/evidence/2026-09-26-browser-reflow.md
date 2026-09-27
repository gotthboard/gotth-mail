# Narrow-screen Extensions reflow — accepted repair

## Scope and mechanism

On the candidate based on `dcd1a46`, a real Chromium session with application
JavaScript disabled reproduced horizontal overflow in the Extensions inventory
and initial detail page. The sole production change is the existing page rule:

```css
main>ul a,h1,dd,code{overflow-wrap:anywhere}
```

Otherwise-unbreakable identifiers, repository text and digests may wrap without
inserting hyphens. Text, hrefs, font sizes, controls, authorization and service
state are unchanged. No clipping, hidden overflow, text shrinking or framework
migration. Existing render complexity still applies; this is a constant template
addition and delegated browser layout, not a performance optimization claim.

The test-only callback retains the original real archive setup and nil-callback
delivery/update/rollback assertions. The browser driver uses a private CDP pipe,
normal Chromium sandbox, native Tab/Enter and read-only diagnostics. Its runner
uses a private user/PID/network/mount namespace, private temporary state and CA,
read-only host root, and only the exact new evidence directory writable on host.

## Red-to-green evidence

Development evidence root:
`/home/linus/.artifacts/gotth-mail-live-browser-20260926/parent-first-gate`.

Targets: Go 1.26.6, PostgreSQL 16.14 (queried 160014), Node 26.5.1 and Chromium
151.0.7922.71. Build metadata was captured while the binaries existed and records
`-race=true` for both final command and UI test binaries.

| Run | Result | Observed scroll/client CSS pixels |
|---|---|---|
| 1 | Equipment error before application execution | Initial evidence mount failed; preserved separately |
| 2 | Product red | Inventory 354/320 |
| 3 | Product red after inventory-only repair | Inventory 320/320; detail 738/305 |
| 4 | PASS, exit 0, 7.34 seconds | Inventory 320/320; detail 305/305 |

Run 3 reached detail using three native Tabs followed by Enter. Its screenshot
confirmed clipped heading, repository and digests before those selectors were
added. Run 4 used identical assertions and driver input logic. Its detail client
width excludes the 15-pixel vertical scrollbar. All four red/green screenshots
were inspected; final text wraps rather than being clipped.

Each application run checks cookie-free 401 and cookie-pair authenticated 200.
Login is explicitly injected, not real OIDC. Independent Go checks compare SQL
registry/secrets/previews/audit snapshots and the current instance, reject/count
browser Authorization, count non-GET and receiver requests, and require an empty
runtime. Those checks pass even on product-red runs. Registration and authorized
fixture cleanup occur outside the measured browser interval.

Normal Browser.close exits 0, with no forced shutdown or live Chromium
descendants. Independent namespace closeout reports zero live fixture processes
and zero residual paths. Credentials travel through private stdin/pipes; retained
diagnostics omit values and raw traffic. Initial secret controls are empty and
hidden CSRF is not painted. This does not establish configured-form secrecy.

## Verification and reproduction

- Final whole `internal/httpui` race suite: PASS, 13 top-level tests (69 test/subtest RUN records), no skips,
  failures or race warnings. Scoped UI/cmd vet: exit 0. Final compiles: exit 0.
- Real delivery and A/B/A regressions passed after shared-fixture extraction
  (4.37 and 7.00 seconds), before the CSS repair. Reused only for unchanged
  fixture/action semantics, not presented as final-CSS lifecycle reruns.
- Formatting, script syntax and diff checks passed.
- Reproduce on development: compile `./cmd/gotth-mail` using
  `GOMAXPROCS=4 go test -race -p=2 -c`, then run
  `scripts/extensions-browser-acceptance.sh TEST_BINARY ALPHA1_ARCHIVE PG16_BIN NEW_EVIDENCE_DIR`.
  Reuse the admitted archive, whose independently fixed digest is checked by the
  fixture. No archive rebuild, host trust edit or sandbox-disabling flag.
- Source snapshots, command outputs, terminal exits, source manifests, build
  metadata and binary removal identities remain in the evidence root.

## Identities

Final reviewed source SHA-256:

```text
d2e62dd888846b90f42153dd40e02cd04cd50e01367fc42d6c0f18c3df718706  internal/httpui/extensions.go
d7ec37d8a6082d5e777181ef1d676d563b01b48c754daa556d3410d44d984416  cmd/gotth-mail/extensions_acceptance_test.go
39d129644a20997fdddfddaaf19056377eb7ef90d7c84b54ccbeeeae8f27f4f4  cmd/gotth-mail/extensions_browser_test.go
8a9f8f350995f25a497ada38cec6075fa41c77faff49a050796095a9c8e18ad8  scripts/extensions-browser-smoke.mjs
3a07a0c5a3d2adf64e3b375a2c3a652f48488e66dc9fc6a09119b52b7a350a4c  scripts/extensions-browser-acceptance.sh
66041de99768b3d0d23ee70a19a8574b11022da8be8739f7d87a43d01b5e33a6  docs/CHANGELOG.md
```

Final raw evidence SHA-256:

```text
0f460d5efdcf0312bfab22c3ebeda6bc686f24106aa55d99f360d689f5798c95  run4.log
950b0347918033ab38a975d43c57f3775a964952c468ebe951c8b7d77ccc586b  run4/browser/proof.json
fe0b707fa75bcab143de99f0e210a5782c4d73c02a7d98ccb6bc25a1031e8b94  run4/browser/inventory.png
69cb32b2477c20139406f84939497205d3f6fba8ec7b7b97d9a6c75e491bcb66  run4/browser/detail.png
5867c1fe427ea0c48a2bbe971699fc0982f570d8464738d74cd1cfad6b5d5659  ui-reflow-race.log
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855  reflow-vet.log
a382d566455f2dea040f751e860e7631baba54cc602abb90dd0b1d95ca99a6d3  final command test binary (removed)
31b99008edf08a432d6092b4c41e7635a66d073dc9395a405e7c1db50162d576  reflow-build-info.txt
8927d7b5569987f2d0d406ff42830c0ad61e4511cde3fdadf2744b33c3f122e5  final UI test binary (removed)
af3739447a445b8ad9f50ee5acad1d2cc45f866d26f331a4791e9871060356c2  ui-reflow-build-info.txt
```

## Admission and remaining gates

Independent reviews `c2b16428-134a-41de-8911-9740ffa9eb4e` and
`2190d793-6dc2-4406-9ad8-8e6628760159` returned PASS/CLEAN for the same six-file
candidate. Both inspected source identities, red/green raw evidence, screenshots,
credential handling, cleanup and verification limits. This later canonical
record is separately inspected by the parent; it was not pre-approved by them.

Four exact inactive test binaries were removed after hashes and actual build
metadata were retained. Required source/evidence remains 7,269,376 allocated
bytes/707 entries. Shared caches were not cleaned. Root inodes remain 5,816,588
of 6,056,957 (97%); task writes used /home ZFS/private temporary filesystems.

Admit only this reflow repair and the first 320px/light/Chromium inventory-to-
initial-detail path. Computed focus samples are not a full focus-visibility or
accessibility audit. Full forms/lifecycle/download/theme/AT, desktop/cross-browser
and font matrices, real login, canonical renderer alignment, deployment and
overall B1/beta acceptance remain open. No workflow completion flag is changed.
