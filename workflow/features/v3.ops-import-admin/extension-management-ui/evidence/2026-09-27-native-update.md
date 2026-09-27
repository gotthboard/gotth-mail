# Native update and separate B readiness — bounded acceptance

## Scope and accepted result
Test-only increment against ecf3cd53c50797ce4aa838945bf3a4d958b16fdb.
Native Preview → blank-confirmation denial → Apply → GET reload makes exactly two
POSTs. Configuration/Test setup and cookie login are injected. Application scripts
are disabled; native keyboard mechanics and normal Chromium sandbox remain intact.
The sibling Preview form stays blank/required and does not obstruct confirmed Apply.

Independent four-table SQL/crypto checks require an actor/instance/revision-bound
B preview, exact payload hash, keyed confirmation/empty-secret binding, ten-minute
future expiry and no premature mutation. Apply consumes only that preview, selects
exact B identities, retains the full independently assembled A version/configuration
snapshot and encrypted secrets, increments revision2→3, clears readiness and stays
stopped/disabled/unrouted. One exact bound update audit is added; prior records and
unrelated authority remain unchanged. AES-GCM authenticates the retained canary.
GET reload preserves the resulting state; A/B runtime paths and routing stay absent.

Only AFTER browser/HTTP shutdown and native SQL/proof checks does a separate
non-browser Service.Test exercise B. Its real child PID231/open executable inode
SHA2566248244fa56bf39554d961019d40d71ece7a68eb5801eca0ef87602272818652, private
socket/process identity and Start→Probe→Stop/absence were observed. Its additional
SQL delta is revision3/tested3/ready plus one readiness audit, not native Update
credit. Configuration, secrets, A rollback snapshot and stopped/unrouted authority
remain intact. Receiver stays quiet. Combined success requires both stages and
final Go/runner success; browser updateGate PASS alone is insufficient.

The existing closed A/B staging block is extracted without trust changes or old
A/B/A call-order changes. B is the existing unpublished version-only alpha.2, not
a new release or schema migration. Current-instance grant/session are negotiated
from verified B bytes. Runner preserves old four/five-argument forms; only update
accepts/requires a sixth B archive argument. No production/workflow change.

## Execution and retained correction
Combined run2 PASS **10.59s**, exit0; browser exit0/no descendants; namespace zero
live fixture processes/residual paths. Go1.26.6/race, PG16.14/160014, Node26.5.1,
Chromium151.0.7922.71,320px/light.

Run1 failed9.85s before Apply/B: the oracle incorrectly required RFC3339 zones for
SQL timestamp-without-time-zone JSON. The corrected UTC layout preserves exact
ten-minute/future-expiry checks. Initial source, raw failure and distinct build
metadata remain retained. This is equipment correction, not product repair.

Race compile/scoped vet pass. Ten preview cases are ONE valid plus NINE mutations.
The 51 shared oracle cases plus five in-body sequence guards ran before the parser
correction; their code did not change. Twenty-five controlled shutdown cases plus
Enter contract pass; native action bodies are stubbed in those cases. No old
physical/full-suite rerun. Ten runner-prefix guards and byte-identical extraction
assertion have worker-transcript-only provenance, not dedicated raw development
logs; reviewers inspected their source semantics but did not independently recover
those historical assertion outputs. Do not claim otherwise.

Development raw root: `/home/linus/.artifacts/gotth-mail-native-update-20260927`.
```text
8baa352e4338ffde9644dbf98b8be87ccba4a7f65cbe86fb96df3e3dc26a1d7c  run1.log
711107743f4b6a3c6ef1708a707045ab54c894f36e04107aa96954197ee39896  run2.log
d8c9d1ac0634dcb4c480becc7f6ca5fa5e7fc7ee86540c714988f0b4f6184c67  run2/browser/proof.json
2cc6d3ae4e494583edbbfe5b125c5e063faef536318e68b30ab350e286abee2e  update-oracles.log
6876532e19b9378f3ecad0c1178c8533eda18fa1bac556d1be5ae71d46666d9e  driver.log
a324f2d1b40394d17107c341b14433e26f7a5f7d4fa0564e2ff83503736e049c  corrected command.test (removed)
```
Reproduce on development with the existing browser runner arguments:
`TEST_BINARY A_ARCHIVE PG16_BIN NEW_EVIDENCE_DIR update B_ARCHIVE`.
Use the already-admitted A archive5cb6043c… and B archived3b79e57… and existing
PG16 prefix; full identities and paths are in the preceding real A/B/A evidence.
Race-compile ./cmd/gotth-mail with GOMAXPROCS=4/p2; focused filters are
`^TestNativeUpdatePreviewOracle$` and `^TestNative(Test|Activation)`.

## Admission and limits
Frozen source manifest SHA256:
`6aac64bf9b5061f7d829b9db6eaa2f7f14426a86de29ce3aea3e7b9e445b2e70`.
Initial→tested differs only in the corrected browser fixture; tested→handoff differs
only in changelog verification prose. All executable inputs are unchanged after
run2. Actual race metadata/hash/stat precede removal; no absent-binary rehash or
final prose-adjusted whole-tree rebuild claim.

Review2 b7062ec9-04db-46b0-9382-5f63e16a8fe3 and review1 completed through
continuation979adec7-f5f7-4bf8-b937-222ba1b452be both PASS/CLEAN with constraints.
Parent separately inspects this later canonical record; neither review pre-admitted
it. This Markdown is the only addition beyond the frozen six-file candidate.

Explicit gaps: no dedicated Apply-corruption matrix, B-postcondition failure
injection or new HTTP negative-action matrix. Source-inspected error propagation,
shared synthetic checks and one physical success do not constitute those tests.
Runtime liveness is sampled; no wire trace, hostile-code sandbox, continuous
monitoring or streaming-memory limit is claimed. SQL/key/confirmation/token data
remain in memory; literal privacy checks are not universal exfiltration proof.

One inactive corrected binary removed23,890KiB/one inode after retained metadata.
Required source/evidence remains7,244KiB/700entries. Shared caches/prior evidence
untouched; development root97%inodes/29%bytes, task allocations off-root/private
tmpfs. Performance/indexing N/A: test correctness only, no production speedup.

This record adds no native rollback, delivery or live OIDC proof. Previously
admitted delivery evidence is unchanged. Renderer/shared reviewed tokens,
presentation and overall B1/beta remain open. No Enable/send/rollback, schema
migration, release or deployment admission follows. Workflow stays open.
