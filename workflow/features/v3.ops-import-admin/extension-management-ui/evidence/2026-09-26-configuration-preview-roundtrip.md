# Configuration preview roundtrip — 2026-09-26

Base: `bc9390dce9253d8fe62fc64d5381f2bc35cb012c`. One bounded native configuration repair; backend authority is unchanged.

## Mechanism

The successful-action epilogue previously replaced submitted preview fields with stored values. It now preserves the successful configure-preview projection. Enum markup selects the exact value and provides an empty choice only where omission is allowed. Required constraints follow existing metadata defaults: defaults permit absence, but neither validation nor projection inserts them. Secret defaults are prohibited; configured-secret retention and preview-bound rotation re-entry remain unchanged. Other actions and errors retain their prior projection paths.

No route, schema, permission, service, runtime, CSRF or confirmation implementation changed. Cost comments account for field/status scans, option copies, formatting and delegated service work; no performance speedup claimed.

## Test-first verification

Development: cached Go1.26.6, native PostgreSQL16.14 (160014), Chromium151.0.7922.71. Baseline production SHA `aa5959c0ae1c8570ae75be90dbbd62b40645c7fa4a81f06699b05dcf9be78317`. New tests and native captures preceded the production edits. Retained route red exits1: all four cases reject ordinary rendered Apply and fail requested SQL persistence. Native red captures show invalid forms, zero submissions and mismatched controls.

Focused race green passes configuration roundtrip and unchanged secret-retention tests. Whole affected UI package race passes without skips; explicit package vet exits0. Four native green cases are valid, submit once and exactly match expected successful controls. No non-secret control is rewritten after preview. Only confirmation and necessary secret re-entry are supplied. Native initial-secret stand-in checks browser validity only; actual secret binding is proven independently by routed SQL tests.

Covered: initial setup and configured edits, true/false checkbox transitions, escaped text, negative/zero integers, nonfirst enums, optional omission/removal/presence, default-backed omission and overrides. Preview leaves instance/encrypted rows unchanged. Apply persists the exact configuration and one revision increment; config-only edits retain encrypted rows. Tamper, missing/wrong CSRF, replay and missing/different rotation re-entry deny without mutation. Existing validation errors and secret-retention regression controls remain.

Reproduction: compile `./internal/httpui` with `go test -p=2 -c` before the fix and `go test -race -p=2 -c` afterward, using the retained dedicated source snapshot. Run `TestExtensionConfigurationRoundtrip` red; green additionally runs `TestExtensionConfiguredSecretRetention` and `TestExtensionSecretFieldRequirement`. Native PG16 PATH and `GOTTH_ROUNDTRIP_REQUIRE_PG16=1` gate the focused run; capture HTML using `GOTTH_ROUNDTRIP_HTML_DIR` in an explicitly writable task directory within bwrap/private tmpfs. Whole UI race runs without a test filter; `go vet -p=2 ./internal/httpui` is separate. Browser script: `node scripts/extensions-configuration-roundtrip-proof.mjs CAPTURE_DIR NEW_OUTPUT_DIR red|green`, with dedicated HOME/cache and default sandbox invocation. No full-repository or unchanged delivery-artifact rebuild.

## Final identities

| File | SHA256 |
|---|---|
| internal/httpui/extensions.go | f4b8fc5a0e37d737e7bd89957e0492ee6e6edc5086aaaf8cab0c2de0bc5dd24d |
| internal/httpui/extensions_configuration_test.go | e90ca5dc54b712028d6808bb86d83aa442e5332c91db4bfcb95e12bdb419da64 |
| scripts/extensions-configuration-roundtrip-proof.mjs | 8e21bac507062b014f7810ba860a4ebb4d498f5f35da771e5e3462c35a8c64f1 |
| docs/implementation/v3-ops-import-admin.md | f0152e0f643d64e593a3c4b9f80e525bba2d4898d2aed20d548d9340617337d8 |
| docs/CHANGELOG.md | 4b90a94a7371d6928aa5b837679b028cc187a6edebb441b9ef78669ddaa656f9 |

Raw evidence retained at development `/home/linus/.artifacts/gotth-mail-config-roundtrip-20260926`:

- red.log: `452f2e86da46d6f5365459de73fdc8d3fbf9a6ab685bfe54d52bbbc712a506c6`, exit1.
- green.log: `c3b3874b58936e32f084d2a4b85967883cf49491a78ec9e8ef6e260ba8af591f`, exit0.
- ui-race.log: `08b357624ef273e630390a9a239f8f3f7775323574ffacf31a5b6f92365ac2b6`, exit0.
- ui-vet.log: empty SHA `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`, recorded exit0.
- Native red initial/final proof: `94c925a0e06b9d9360dc2693ff69983c1bf50cf2d0dec0546167fbe21f495faf`.
- Native green initial/final proof: `b2fa0ff2b8a1a212c29fff4741e38ba18377b4190a7bbe11a4145a5770a3808c`.
- Capture manifest: `0f5b5461b0ca7e0407436b53959b94d8059e2fc6a74f296f3da9aba7d87c6340`.

Successful execution of the red binary supports its build success; no separate compile-red.exit exists. Timestamps corroborate test-first order, not tamper-proof provenance. Original evidence remains preserved.

Independent reviews `65b1280a-13d3-4bd3-bdc4-c5ca5abfe2bf` and `27dd1d16-c6b7-4e87-8c6f-c460d65aaa51` PASS. Only changelog references changed between reviews; second reviewed final hashes. Parent inspected complete delta/tests/script/contracts and raw identities, and inspected this evidence record before admission.

## Resources and non-waivers

Exact inactive test binaries and task browser-home/profiles were removed after hashing; source/logs/captures remain: 7,530,496 allocated bytes/738 entries. Profile peak sizes were not measured. No live task processes at handoff; namespace cleanup stopped PG and removed temporary state. Development root remained97% inode-used (5,817,115), with no task-attributed root growth; explicit work stayed /home ZFS/private tmpfs. No unrelated cleanup or host trust/system changes.

Required confirmation still obstructs re-preview while blank. This remains the next bounded repair: current captures observe confirmation validity, not an actual re-preview click. Not waived. Captured HTML plus separate routed SQL is not live authenticated browser-to-SQL acceptance. Integer extremes/stored JSON float precision, keyboard/no-JS/theme/mobile/accessibility, audit link, identity, signing and final beta gates remain unproved here. No release, merge or deployment admission.
