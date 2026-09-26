# Real A→B→A update/rollback checkpoint — 2026-09-26

Base c0de075b1e61085a021be2679d2a9ceb44170d7a. Test-equipment extension only; no production changes.

## Scope and immutable identity

A is the previously verified alpha.1 archive5cb6043ca200acfa67d4c6a85e0c1ba070c51dc550cacca7ce538021c8d9e83a, binary616d9fd3e99543f5dbfa92f526d51551b3883815881213fd7ba44338f4c83994. B is the existing reproducible, unpublished version-only alpha.2 candidate from admitted webhook source3627c43213b82afa290372a6e2d9c36978a54758: archive d3b79e577bc68aedcb83b8c3cc378341cf8610db514c751be3ff331df9a8937a, binary6248244fa56bf39554d961019d40d71ece7a68eb5801eca0ef87602272818652, manifest4093f2b17c2b8062d0f3ceb27480c77865289ec883c642798cd19352a8cab9ea. No new package build, tag or release. Both original archives were rehashed unchanged after execution.

Closed two-pin fixture verifies bounded archives/members and canonical manifests before execution. Real manifest-derived grant/session identities bind the same SQL instance. No arbitrary caller-selected trust digest, generic installer or product binary-rehash claim.

## Observed behavior

Actual cookie/CSRF HTML handlers and production runtime/SQL perform confirmed update and rollback. Enabled update/rollback, wrong confirmation, forged/consumed preview and pre-Test Enable are denied without changed registry or receiver activity. Preview displays exact target with no applied mutation. Update records B/previousA, increments revision, clears readiness and stays stopped until Test/Enable.

Namespace-private /proc/PID/exe hashes establish actual A→B→B→A live executable identities, not SQL pins or separate version output. B then reconfigured B independently deliver authenticated HTTPS/HMAC alerts. Reconfigured B uses /candidate-b and timeout2 instead of A root path and timeout1, and a newly rotated ephemeral key. Rollback restores A configuration, metadata, capabilities/interfaces/slots and manifest/grant/session, retains B as previous, resets readiness and remains stopped. Restored A rejects the old receiver-key expectation and successfully authenticates using the retained rotated key at the restored endpoint. Secrets are not version snapshots.

Atomic immutable receiver expectations bind key/path/exact JSON; receiver verifies bounded wire-body HMAC and headers before success. SQL results are reread and correlated. Final Disable leaves no runtime files and blocks another unique alert. Existing three-argument delivery runner behavior is preserved; optional fourth artifact selects the update/rollback case.

## Verification and retained failure

Development: Go1.26.6, native PostgreSQL16.14 queried160014, bwrap0.11.2; private namespaces and standard CA roots, unchanged closed production child environment. Compile dedicated snapshot with go test [-race] -p=2 -c -o ../mail[-race].test ./cmd/gotth-mail. Invoke scripts/extensions-delivery-acceptance.sh TEST_BINARY ALPHA1_ARCHIVE PG16_BIN ALPHA2_CANDIDATE.

Focused normal PASS2.24s; race PASS7.09s; original three-argument delivery regression race PASS4.44s. Full affected cmd/gotth-mail race package PASS; its only skips are the two opt-in artifact cases, each separately executed without skip. Formatting, shell syntax and diff checks passed. No unchanged full-repository or extension-package build rerun.

Initial normal fixture failed because its uppercase class expectation disagreed with documented SanitizeAlert/boundToken/normalizeToken lowercasing. Only fixture labels were corrected; exact independent body/MAC oracle preserved. This is not a product defect or manufactured production red. Raw failure retained.

Final source SHA256:
- cmd/gotth-mail/extensions_acceptance_test.go:3b95bf157ec43e419871bde7d47db2faa2eca4f78d6c2bccc2fb7267a088990e
- scripts/extensions-delivery-acceptance.sh:c9e30833b26bf7a5a43b02bdca91139c7a94a00c38d7ee838892f26dc66be497
- docs/CHANGELOG.md:d77b147ba961914da50d708f7bad47f666d555ac90f5d733bd96ef014cff6015

Raw development /home/linus/.artifacts/gotth-mail-real-update-rollback-20260926:
- acceptance-normal.log (initial FAIL):1f3ddc60a469f3f5d287bb25ce6d62253d444961dbad1f6cc6395dbef8e065ab
- acceptance-normal-final.log:659d802a9b2f5c4963a669759914c9f0302a4f23cf0e1ac86feb455bab23f7c3
- acceptance-race.log:23a4ef6653d81b8097022644f8b3dc7eed99862a0f9b6284fd755b8059b768f3
- delivery-regression-race.log:3dafac0bdbe4b6a310366e57cf1b1b0e6358d11c30381b14f4f95c24c667b067
- cmd-package-race.log:40d735d337bb1ec5da489d32663a21d4eb0680ac048c0f53b13315b6779dcd68

Independent cold reviews40d9eb92-bfe7-4afb-9c0a-8be8224c4f12 and28e94388-4048-4363-a2ea-36403364d9ce PASS; executable hashes unchanged between reviews, final documentation reviewed by second. Parent verified complete delta and source/log identities, and admits this bounded checkpoint.

## Resources and remaining gates

No live fixture processes at handoff and reviewers inspection. Exact inactive test binaries removed after hashing; private namespace CA/key/PG/runtime data destroyed. Required source/log tree retained ~6.66MB/646 entries before final archive-hash text; shared bounded caches reused. Development root remained97% inode-used (5,817,070→5,817,072); concurrent host byte/inode delta is not attributed to this task. Explicit outputs stayed /home ZFS/private tmpfs; no unrelated cleanup. Performance N/A: test equipment only, no production-cost change or speedup.

Mocked login and in-process Mail handlers, not browser/live OIDC/deployed server. Identical metadata schemas across version-only artifacts do not prove a schema migration. Native browser/no-JS/keyboard/theme/320px, broader roles/audit/secret-form/signing and final beta gates remain open. No workflow completion, merge, release or deployment is authorized by these results.
