# Native initial configuration — bounded acceptance

## Scope and disposition

Test-equipment increment against c13f5ffd26ac8a52d9fe63f7cd2c0d6b95a80b85.
One real initial Preview → blank-confirmation denial → Apply → GET reload.
Production, renderer, schema, dependencies and workflow state are unchanged.
Canonical templ/Tailwind/HTMX and shared reviewed token alignment remains a
B1/beta blocker; this is current-renderer functional evidence, not a waiver.

The existing independently pinned alpha.1 archive, real mux and PG16 fixture
supply the private endpoint, random canary and injected cookie identity. Native
Tab/character/Enter actions operate ordinary forms with application scripts
disabled. Read-only observations check the visible reviewed target, untouched
accepted hidden scalars, blank password controls and displayed confirmation.
Blank confirmation sends no POST; there are exactly two POSTs in the complete
pair. Reload is an ordinary GET, not POST replay.

The Go response-completion barrier checks each phase before releasing its
response. It rejects unexpected routes/query/methods/actions/phases/replays and
bearer headers. Independent checks prove:
- One actor/instance/revision-bound unconsumed preview with the selected endpoint
  and numeric timeout 2; instances/secrets/audit unchanged during Preview.
- The same preview is consumed; configuration revision advances 1→2; tested
  readiness clears; the instance remains stopped/disabled/unrouted. Unrelated
  instance authority/pins are preserved.
- Exactly one encrypted secret row with expected metadata; independent AES-GCM
  decryption using instanceID + NUL + slot AAD equals the original canary in memory.
- Original install audit unchanged; exactly one correctly bound configure success
  audit. Its configured_secret_slots value is [REDACTED], not a visible slot list.
- Applied state persists unchanged on reload; empty runtime, no observed managed
  executable at boundaries, zero fixture receiver traffic and no response
  canary/session reflection. Retained diagnostics exclude private inputs.

Registration and existing authorized Disable cleanup are outside the measured
browser interval. No browser Test/Enable/send/update/rollback action is credited.

## Failure, correction and results

Initial run1 failed (12.60s/exit1, phase0/posts0). Its PRODUCT_RED label was
premature: the link-oriented helper omitted the Enter keypress carriage return
required by native buttons. Pinned Chromium151 HTMLButtonElement default handling
and HTMLElement::HandleKeyboardActivation establish the contract. Configuration
alone now uses rawKeyDown → char CR → keyUp; the old helpers remain unchanged.
No product defect or production repair is inferred. Run1 remains retained.

Final run3 PASS, 8.31s, exit0: Go1.26.6/race, PostgreSQL16.14 (queried160014),
Node26.5.1, Chromium151.0.7922.71, normal sandbox, no app scripts, 320px/light.
Unauthenticated inventory401, then detail/Preview/Apply/reload200. Independent
SQL/AES-GCM/audit/privacy/runtime checks pass. Browser exits0 with no descendants;
namespace live-process and residual-path counts are zero.

Scoped vet, race compile, eight barrier rejection cases, ten controlled shutdown
cases plus actual Enter-helper contract, syntax/format/diff checks pass. Controlled
shutdown cases stub configuration actions; they are not physical form or OS-signal
evidence. No old physical layout/audit/lifecycle or full repository suite rerun.

Raw development root:
`/home/linus/.artifacts/gotth-mail-native-config-20260927`

```text
b9d91027b6fc53f3eae8bc5a10d6fba4c9e50e202893a9c6a071365d586be9c0  run3.log
bc0f776a4c5ea3d137348fb7de1165286af4b62f63fe18483e68f39128fe4430  run3/browser/proof.json
95c7e5570415b33bdeeaf9ba0a66e017063e12053e4be326070999111e6c083d  final-driver.log
9e31b2648e85d8444e58937258574a53811e1db583b7fd836ce7639d7f51ee56  final-barrier.log
b4818647b2f3a3db57cabe2f5764b7af13761883e09cdedfbe3f9aa4783893a5  final command test binary (removed)
5cb6043ca200acfa67d4c6a85e0c1ba070c51dc550cacca7ce538021c8d9e83a  admitted alpha.1 archive
```

Reproduce on development: `go test -race -p=2 -c ./cmd/gotth-mail` with
GOMAXPROCS=4, then the existing browser runner with fifth argument `configuration`.
Run `node scripts/extensions-browser-smoke.test.mjs` and the compiled test binary
with `-test.run=^TestConfigurationBrowserBarrierRejectsUnknown$ -test.v`.
Use the admitted archive, existing PG16 prefix and a new private evidence path.

## Exact review and tested-to-final mapping

Final parent 483-path manifest SHA256:
`3c3472f97a1d1792554ae066bc61e93e5dbeefd7f58b209002e99f1071426454`.
Changed source identities:

```text
0c82fa586edd55c69880e9c91d3c19cc8f23eb9ef85271dcb6e43f8e8248c08f  cmd/gotth-mail/extensions_acceptance_test.go
d46f10f330cd5f0d9bc38a122381bfe3ad3f287a27b838ed90a3d9eb37033784  cmd/gotth-mail/extensions_browser_test.go
95416fd163a6eef9fd3d3b3affe9d233b8597f866bd4458c9699d2f699e3ed7b  scripts/extensions-browser-smoke.mjs
a02f154020b44e1b2a14b8bf0a2f68b4dfb50977cf032d61c72ff210c7345653  scripts/extensions-browser-smoke.test.mjs
aea11d5f9e9ccbee879823bfb18929fbcf9568bbf675a25f9b62ab523d28654f  scripts/extensions-browser-acceptance.sh
93e33cf65e0663ed28875a0e0d6b2839b37a4d54090e691e92889483f2e61bde  docs/CHANGELOG.md
```

After run3, only ordinary first-line comments in driver/runner and changelog
closeout changed; retained tested files and exact closeout diffs prove that mapping.
Parent additionally pinned the preceding changelog entry to c13f5ff. Go and driver
fault-test bytes match tested inputs; no executable script/directive or line-count
change. Final full script bytes were NOT rerun. Actual race metadata was captured
before binary cleanup; no new absent-binary identity or final-byte rerun is claimed.
This later evidence Markdown is the only addition beyond the reviewed freeze.

Independent review1 07932176-66dd-4208-b251-edbac4af2581 and independent review2
completed through continuation f72a361a-42d5-4e0d-a579-2f5abc1f98a7 both return
PASS/CLEAN with scope constraints. Review2 initial ba9e381d timeout was reconciled
and resumed without restarting completed tests or review1. Parent separately
inspects this actual canonical record; neither report pre-approved unwritten text.

## Limits and resource accounting

Injected login is not durable OIDC/session/revocation proof. Four named SQL tables
are checked, not the entire database. Process observations are not continuous
tracing. Literal privacy scans are not universal encoded-leak detection. The 1MiB
response check is post-materialization fixture checking, not a streaming cap.
Client constraint denial is not a new adversarial server-side confirmation test.

Two exact inactive test binaries were removed after retaining actual build/hash/
stat records (23,730/23,722KiB and one inode each). Required source/evidence remains
7,402KiB/714entries; shared Go caches remain untouched. Development root remains
97% inodes/29% bytes; task build/cache/tmp placement was off-root. No unrelated
cleanup or host-policy change. Performance N/A: test correctness only, no production
or speedup change. Graph/indexing N/A for this bounded direct closeout.

No broader lifecycle, presentation/theme/accessibility, identity, release or
deployment admission follows. Renderer alignment and remaining beta gates stay open.
