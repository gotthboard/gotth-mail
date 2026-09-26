# Configured-secret native constraint repair — 2026-09-26

Base1eaac1ad449ec9ae09245ccd9f968e4f786f278d. Eight behavioral lines in extensionFields plus explicit cost comment; no backend/template/router/auth changes.

## Contract and fix

Required write-only secret inputs previously stayed blank AND native-required even when their exact slot was configured, blocking backend-supported retention. Only exact matching configured status now relaxes the field required projection. Field.Name is its granted slot identity; no alias exists. Optional fields stay optional; missing/unconfigured/unrelated statuses cannot relax a required field. Secret values never populate rendered controls.

Configuration-only blank secret leaves encrypted nonce/ciphertext/key_version/configured_at/rotated_at unchanged while ordinary configuration and revision advance. Explicitly previewed rotation still binds identical secret re-entry; missing/different re-entry is rejected. Initial missing required secret can be staged by backend but cannot pass Test/Enable. Existing actor, CSRF, confirmation, payload, revision and preview-consumption authority is unchanged. The scan has no extra per-render map and documents field/status/option/value costs without a speedup claim.

## Test-first evidence

Development Go1.26.6, native PG16.14 (queried160014), Chromium151.0.7922.71. Tests and actual-route HTML captures were produced before production changes. Red-tests exit1 showed configured-required projection failures and route required=true; unrelated controls and backend retention/rotation checks already passed. Native Chromium captured detail and preview: blank secret, required=true, invalid, zero submit events.

After the minimal fix: focused race exit0/PASS1.31s; exact final whole internal/httpui race exit0/PASS with no skips, including prior fifteen update-confirmation boundary cases; explicit go vet -p=2 ./internal/httpui exit0. Gofmt, script syntax and diff checks passed. Native captured detail and preview now show blank secret, required=false, valid, one submit event. No secret value, disabled field, novalidate or formnovalidate bypass.

The script fills ordinary endpoint/confirmation controls, calls native checkValidity and button.click, and prevents navigation only on the successful submit event. It does not rewrite validation attributes; production deliberately changes the required projection. Chromium launch does not disable its sandbox. Default-sandbox invocation is not independent OS-sandbox attestation.

Real cookie/CSRF route POST tests separately prove encrypted-row invariance, configuration/revision change, missing/wrong CSRF, wrong confirmation, tampered payload, replay, and missing/different/matching rotation behavior. Bound login is mocked; runtime is a sentinel proving missing-secret denial before Start. Six projection cases and unsupported alias rejection cover changed behavior. No numeric coverage claim.

Reproduce in a dedicated development snapshot: go test -p=2 -c (red), go test -race -p=2 -c (green/final), run focused TestExtension(SecretFieldRequirement|ConfiguredSecretRetention) with native PG16 PATH, GOTTH_RETENTION_REQUIRE_PG16=1 and task-owned GOTTH_RETENTION_HTML_DIR under isolated bwrap/private tmpfs; run whole UI final binary without test filter and go vet. Browser: node scripts/extensions-secret-constraint-proof.mjs CAPTURE_DIR NEW_OUTPUT_DIR blocked|valid, using dedicated HOME/XDG cache and fresh disposable profiles. No accepted package A/B/A rebuild or unchanged full-repository rerun.

## Final identities and raw records

- internal/httpui/extensions.go: aa5959c0ae1c8570ae75be90dbbd62b40645c7fa4a81f06699b05dcf9be78317
- internal/httpui/extensions_secret_test.go: 1e8507e2f0358b8b1a559fdd07fefb9b5e621b8f4e3ef8d2bbf9756953c298de
- scripts/extensions-secret-constraint-proof.mjs: 786987ac4c0f27d122876afbedd30f8b17bb4f4fb9f23cd08e0e94426fbd528d
- docs/implementation/v3-ops-import-admin.md: eee07566c3258cd784c227c1d99cf76a0d8a0485dc7f6996f7b98307bb8bb061
- docs/CHANGELOG.md: 81e8e2e4aebf7d3b0a48812b9420572eec5b4ee550565ec394f97c04cd39a584

Development /home/linus/.artifacts/gotth-mail-secret-retention-20260926 retains source, raw captures, DOM, scripts, logs, terminal exit files and removed-binary hashes:
- red-tests.log: a35af07460a5d053b5dc72a64a9a7f19ee7d60e5bb4190bdebfdd1882476bf2c
- green-tests.log: 90544ba553c3270fe42703d136cbc583cee81aa18ff0fad96c753079ad8f7e45
- ui-package-race.log: 4f79018b94ee26044d20ad18fe8d7e51108dc7c103a755e64213d08e9d402eda
- ui-vet.log: empty, e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855, recorded exit0
- browser-red/proof.json: 49562752d373fe5a68133c832d61a3c6ca91f9edc9eb37abe4222978dc0832ab
- browser-green/proof.json: bce8ad04429215999485462d340cf7f923fadeffbfcee860a5c24048749c5093

Independent reviews ec595000-8f8d-48ce-b906-25a2a799eceb and72a9104b-7cc1-45a5-85d6-2f45b7ab498e PASS. Production/test/script/spec unchanged between reviews; second reviewed final changelog references and clarification. Parent verified exact identities, complete new source/script/tests/docs and actual red/green/terminal records. Admit this repair only.

## Resource accounting and limits

Only explicit inactive disposable test binaries and task browser-home/profiles were removed. Required source/evidence retained6,928,384 allocated bytes/678 entries; shared caches reused. Per-profile peak sizes were not measured. No live task test/browser processes at handoff. Root inode count stayed5,817,090 (97%); small concurrent byte delta not attributed to task. Builds/snapshots stayed development /home ZFS, database fixtures private tmpfs; no Docker/system/trust changes or unrelated cleanup.

Browser result is captured-route native constraint proof, not live browser-to-SQL or login acceptance. The pre-existing configuration-preview overwrite remains: captured preview displays the old endpoint, and this narrow proof re-enters the intended non-secret value. That issue is explicitly NOT fixed or credited here. No real extension execution, full secrecy audit, native keyboard/no-JS/theme/mobile/accessibility, audit-link, signing, identity, performance measurement, release/deployment or full beta admission. Remaining gates stay open.
