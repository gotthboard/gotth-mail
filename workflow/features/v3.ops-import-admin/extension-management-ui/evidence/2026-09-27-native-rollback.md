# Native rollback and separate restored-A readiness

## Bounded admission
Test-only increment against b57d641cf293d9534641fb3cc503de68f41d2ac6.
Setup independently captures configured/tested A before B update, then changes
B endpoint/timeout, rotates the canary secret and tests B at revision4. Setup is
not native-browser credit. Stored previous-A is checked against captured A, not
used as its own expected value.

Native blank confirmation is blocked without POST. Wrong nonempty confirmation
is POST1 and leaves all four SQL-table snapshots unchanged. Correct displayed
confirmation is POST2, followed by GET reload. Native Tab/Enter/character input
and Ctrl+A/Backspace perform the actions; no DOM mutation or scripted submission.
Application scripts are disabled, cookies injected, normal Chromium sandbox used.

Independent SQL requires full A artifact/manifest/grant/session, permissions,
metadata and configuration restoration; complete current-B snapshot becomes
previous. Revision5 is untested/unknown/stopped, disabled/unrouted. Current rotated
secret rows, ciphertext/timestamps and previews remain unchanged. AES-GCM with
instance-plus-slot AAD authenticates the retained canary. Exactly one bound rollback
audit adds beforeB/afterA while preserving prior events (6→7). Native runtime stays
absent, exact public Health no-route result holds and receiver count stays zero.

Only after browser/HTTP shutdown and native SQL/proof checks does a separately
labeled non-browser Service.Test prove restored A. PID229 and live open executable
inode SHA256616d9fd3e99543f5dbfa92f526d51551b3883815881213fd7ba44338f4c83994,
private socket/files/process binding and Start→Probe→Stop/absence were observed.
Additional SQL is tested5/ready/updated_at plus one Test audit (7→8), preserving
all other authority/secrets/previews. Combined success requires both stages and
final Go/runner success; native browser PASS alone is insufficient.

## Verified execution
First physical run PASS **10.56s**, exit0. Browser exit0/no descendants; namespace
zero live fixture processes/residual paths. Go1.26.6/race, PostgreSQL16.14/160014,
Chromium151.0.7922.71,320px/light.

Scoped race compile/vet pass. Seventy-six named oracle cases comprise15 rollback,
10 update-preview and51 shared cases. Four in-body combined-decision permutations
and five sequence guards also pass. Thirty controlled driver shutdown cases plus
Enter contract, and14 retained prefix-only runner checks pass. Synthetic driver
action bodies are stubbed; decision permutations test supplied boolean/error
results, NOT actual child failure or execution ordering. Ordering has separate
source and physical-log evidence. No old physical/full-suite reruns.

Initial pure valid-fixture failure used non-JSON table placeholders. Corrected
fixture strings and diagnostic detail only; actual oracle unchanged. Initial and
diagnostic exit1/source/build evidence remain retained. Corrected checks preceded
the first physical run. No product defect or production repair was hidden.

Development root: `/home/linus/.artifacts/gotth-mail-native-rollback-20260927`.
```text
ec280ce516c9a3ab3cdc2610377e86ff78dad2f1b5a9106f511761e40a97d727  run1.log
74b3e0e07f422579ec9089e047dfcf0c06014c089c3e61a54c0f5d9e94a84149  run1/browser/proof.json
4b9561c552739e81231f425cdd2a37fd209688dc40482a2d4d9a5c6b4aac3189  oracles.log
670d61552ff05727533af7e46be1386287903ebdc4a259d556b4b752a9761e5c  driver.log
03e0284dd8bfec5b3795c03c63548f51ad27471fb82db186d5673960b7e0bc0e  runner-arguments.log
ee354687d0668d6b99beb4c6b03fa8426674117eaa51771928b4518d6d6abadb  corrected command.test (removed)
```
Reproduction uses the existing browser runner:
`TEST_BINARY A_ARCHIVE PG16_BIN NEW_EVIDENCE_DIR rollback B_ARCHIVE`.
Reuse pinned A/B archives and PG16 prefix documented in preceding real A/B/A
evidence; no new package build. Compile ./cmd/gotth-mail with Go1.26.6/race,
GOMAXPROCS=4/p2 on development. Focused filter: `^TestNative`.

## Source and review mapping
Frozen manifest SHA256:
`330b7668b44467731ba60bd5147cfb980abfe4c15c29156b74813ac913b3c252`.
Initial→tested differs only in synthetic browser-fixture correction; tested→final
handoff differs only in changelog verification prose. Executable inputs unchanged
after physical execution. Retained binary metadata/hash/stat is historical proof,
not a fresh rehash of removed bytes or a final-prose-adjusted whole-tree rebuild.

Independent c40469b6-c2fd-45c2-b285-db8438a58aef and
bd5aa615-dbdf-42e7-b2ff-235c6385b179 both PASS/CLEAN with constraints. Parent
separately inspects this actual later record; reviews did not pre-admit it. This
Markdown is the sole addition beyond the reviewed six-file freeze.

One inactive corrected binary removed23,962KiB/one inode after captured metadata.
Required evidence/source remains7,091KiB/699entries; shared caches/prior evidence
untouched. Development root97%inodes/29%bytes; allocations off-root/private tmpfs.
Performance/indexing N/A: bounded test correctness, no production speedup claim.

## Limits
No new delivery or independently observed B-process claim; prior admitted delivery
evidence remains unchanged. No broader actor/CSRF/expiry/crash/recovery matrix.
Liveness is sampled; SQL assumes known migrated fixture shapes. Response-size
checks follow materialization, not streaming bounds. Privacy scans are bounded
canary checks, not universal secret-flow proof. Inherited TestB names/B-worded
errors remain compatibility labels; actual rollback selection/log proves A.

No production, trust, confirmation, workflow-state, release or deployment change.
Renderer stack/shared reviewed tokens, responsive/a11y/theme presentation and
overall B1/beta remain binding and open.
