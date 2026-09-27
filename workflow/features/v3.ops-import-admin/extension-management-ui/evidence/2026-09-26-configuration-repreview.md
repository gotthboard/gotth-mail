# Native configuration re-preview — 2026-09-26

Base: `f50e07cda3cd9d3003309888f595966b1238179e`. Bounded form-ownership correction, not full browser/beta admission.

## Mechanism and preserved authority

Separate sibling POST forms replace the shared configuration form. Preview owns editable fields and validates them without Apply confirmation. Apply visibly identifies the reviewed configuration and submits its own accepted non-secret controls, CSRF, preview ID, blank secret re-entry and required confirmation. Editing or invalidating Preview does not change Apply’s target.

False boolean has no hidden control; true submits `on`. Empty optional/default-backed scalars remain empty and are omitted by the unchanged adapter. Secret values never appear in summaries or hidden controls. Existing html/template escaping remains. No JavaScript dependency, novalidate, formnovalidate or disabled-control workaround; no dispatch, service, authorization, CSRF, projection or database changes. Extra bounded summary/hidden markup adds rendering/output cost, not a new projection copy or service call.

Creating another preview does not consume previous previews. Existing actor, revision, expiry, payload, secret-map and confirmation binding govern Apply; consumption and mutation remain transactional. No latest-preview-only rule was added.

## Verification

Development: Go1.26.6, PostgreSQL16.14 (160014), Chromium151.0.7922.71. Baseline production SHA `f4b8fc5a0e37d737e7bd89957e0492ee6e6edc5086aaaf8cab0c2de0bc5dd24d`. Actual native Preview button.click red preceded production changes: all four captured cases had blank confirmation and zero Preview submit events. Route red exit1 specifically reported shared confirmation ownership; backend controls already worked.

Focused race green passes re-preview and unchanged secret-retention cases. Whole UI-package race passes without skips or race reports; explicit vet exits0. Native green: edited Preview submits once with blank Apply confirmation; invalid ordinary Preview remains blocked; blank Apply remains blocked; confirmed Apply submits its exact accepted controls despite invalid Preview edits. Independent expected controls and visible summary match; summary stays unchanged. Typed-roundtrip and configured-secret native regression proofs also pass.

Real cookie/CSRF route tests with PostgreSQL create A then edited B previews, check fresh IDs/tokens and two unconsumed rows, and prove no instance/encrypted-row mutation before Apply. Empty/wrong confirmation, mixed old token/new payload, tampering, missing/wrong CSRF, missing/different rotation secret, replay and old revision after B applies are denied. Matching Apply persists the exact typed configuration and one revision increment; configuration-only edits retain exact encrypted rows.

Old A applying successfully before any later mutation is supported by unchanged source plus its unconsumed-row check; no separate old-first success test was run. Native secret stand-ins prove browser constraints only; routed SQL independently proves actual preview-bound secret re-entry. Retained timestamps corroborate historical red-before-fix execution, not cryptographic execution attestation.

### Reproduction

Dedicated development snapshot: `/home/linus/.artifacts/gotth-mail-config-repreview-20260926/source`. Compile `./internal/httpui` with `go test -p=2 -c` for red and `go test -race -p=2 -c` for green; run `go vet -p=2 ./internal/httpui`. Use native PG16 PATH, private bwrap/tmpfs state and `GOTTH_ROUNDTRIP_REQUIRE_PG16=1`; red selects `TestExtensionConfigurationRoundtrip`, green additionally selects configured-secret retention/required tests. Whole UI race runs without a filter and with the PG16 requirement flags. Capture HTML through the task-owned explicit capture directories.

With dedicated HOME/cache, run `scripts/extensions-configuration-repreview-proof.mjs CAPTURE_DIR NEW_OUTPUT_DIR red|green`; run existing roundtrip and secret-constraint scripts against green captures. Chromium uses its default sandbox invocation and fresh disposable profiles. Proof instrumentation intercepts submit only after native validation; it does not overwrite accepted Apply controls. No full-repository or unchanged packaged-delivery rebuild.

## Final identities

| File | SHA256 |
|---|---|
| internal/httpui/extensions.go | 68069c14a37e37bb5113b340c33fd11dc36de72af6389db82d96e494ba77d438 |
| internal/httpui/extensions_configuration_test.go | 5a5f2740b4543cb28926ce0fcc561629e25d2d40b560aa1fb3e3d0aa6b00b8fd |
| scripts/extensions-configuration-repreview-proof.mjs | 16275c90e726d760770014081eb79d4ea104f0034d3e55030af7d96b0c33b4e6 |
| scripts/extensions-configuration-roundtrip-proof.mjs | b75160c1aab99b86663bbbc07ba61e5de2a3c413838b9bc3ccb2b461d6b82c22 |
| scripts/extensions-secret-constraint-proof.mjs | f6ca7ec503c5e6037dc680b2d69629238fc1c2b3be34a75afc0d6094f9fdb4e1 |
| docs/implementation/v3-ops-import-admin.md | 4f1cb7a7186e194fcc68fc39c135bf316501147e89d45d97d1fbf768345d3e33 |
| docs/CHANGELOG.md | 005016ef44fbf851c62cbfcfe8447d9405af271a68e736439063716b37d837c7 |

Raw evidence under development `/home/linus/.artifacts/gotth-mail-config-repreview-20260926`:

- red.log: `924b4030eafbd5cd94f3b9dfa17f9c97959ea781f47c542e105c5bc9506009bd`, exit1.
- green.log: `32ca0e4ae1f9d3cd1b9366743f8fe046d2fc9d2ba13cc9e8923d6a9339f7f8a0`, exit0.
- ui-race.log: `730350a613548ba03a5cb5e88a916f379c9e8449ca1deb039b019f8fc237ed26`, exit0.
- ui-vet.log: empty SHA `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`, exit0.
- browser-red/proof.json: `c37834dfc04362aab8d9f7324abe4d78d7bbabecbefa5209cf8fa94dc3f0b24d`.
- browser-green/proof.json: `6b651392c2bb102e43afd02a6fcf37ee9661e3b42790510dfc4b7f05792856ad`.
- browser-roundtrip-final/proof.json: `43b3de9982480e3120598ea790fa241a66e04cad8872cc0633a8fe890c88ec85`.
- browser-retention/proof.json: `bce8ad04429215999485462d340cf7f923fadeffbfcee860a5c24048749c5093`.
- capture-sha256.txt: `a2250dc2debf8d3bd527a38288ad7e532a1bed1b29561f5c36b673ac7694c2f1`.

Both compile exits and all five browser invocation exits are0. Required source, raw captures, expected controls, DOM, logs and binary hash records remain preserved. WHATWG ownership/validation/submission/entry-list algorithms informed the mechanism; retained extract SHA `f68e197ad927cb6a300d962bbcd6ed2912afe3cc5133c79434dc2d64ccf3f628`.

Independent reviews `f4287dc7-04d8-41d6-b9e6-190c8e6f8a86` and `f60b4198-c12e-454d-9084-1cf301aba2ce` PASS. Only changelog references changed between reviews; second checked final seven-file identities. Canonical evidence is a separate parent closeout, not pre-admitted by those reviews.

## Cleanup and limits

Exact inactive test binaries, task browser-home and temporary profiles removed after execution/hashing; no task processes at handoff. Private namespace teardown removed PG/tmpfs state. Required source/evidence retained7,882,752 allocated bytes/754 entries. Profile peak sizes were not measured. Development root inode count stayed5,816,514 (97%); small host byte delta not attributed to task. Explicit outputs stayed /home ZFS/private tmpfs; no unrelated cleanup or system/trust changes.

Captured native HTML and separate SQL routes are not a live authenticated browser-to-SQL flow. Session lookup is mocked. Configure-specific actor/expiry matrix, live OIDC, actual extension execution, keyboard/no-JS/theme/mobile/accessibility and full beta are not newly proved. Audit-link work remains queued. No merge, release or deployment admission.
