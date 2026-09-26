# Extension recovery checkpoint — 2026-09-26

## Scope and identity

Verified recovery checkpoint only; extension-management-ui and beta acceptance remain open. Base source: `79db740867f5da0d016fcae7dbf5a779c19fbffc`. The twelve-file reviewed patch had dirty fingerprint `49696b7c300bb8ddcc6ccd2d989119fed1746a59170a99335f2669033237bf31`; parent verified all twelve file SHA-256 values unchanged before commit. This evidence summary is the only addition after frozen-source review. No production deployment, release tag, root-feature completion or automatic grant admission.

## Behavior proved

- Startup transactionally invalidates historical routing and audits changes while preserving intent/configuration/pins/grants/secrets.
- Explicit recovery revalidates exact runtime binding, configuration, scoped secrets, authenticated handshake and health; failed transitions do not silently restart or re-admit.
- Deterministic held-handshake regression proves observational Health cannot clear or grant lifecycle readiness between explicit Probe and Admit.
- Protected unknown runtime contents quarantine only the extension. Seeded SQL/audit assertions and a configured Postfix TCP request prove unrelated host availability. Unknown files/processes are not adopted/deleted/signalled.
- Native Recover / revalidate retains Disable and existing roles/CSRF/ordinary HTML POST.
- Real webhook parent-SIGKILL fixture proves that exact child stops and its socket refuses connections; protected residual secrets remain. Recovery requires verified exact cleanup, restart and explicit activation.

## Verification and independent admission

Development host, Go1.26.6, PostgreSQL18.4, task-owned off-root data/cache; `go test -p=2 -count=1 -race -coverprofile=...` over complete packages:

| Package | Result | Statement coverage |
|---|---|---|
| internal/extensionsruntime | PASS |76.2%|
| internal/extensionsadmin | PASS |76.6%|
| internal/httpui | PASS |60.6%|
| internal/api | PASS |65.4%|
| cmd/gotth-mail | PASS |69.9%|

Scoped vet and `git diff --check` PASS. Deterministic race regression preserved honest red and three-run green; isolation fixture preserves initial wrong-recipient failure and corrected green. No skipped case is substituted for actual artifact proof.

Independent frozen-source reviews `01ac3a0e-54c2-4fb2-a781-01a32ce7aa4f` and `2f39c56a-e83a-4e03-8540-16e68cfa4a10`: PASS for this checkpoint, not release admission. Parent source/evidence review: accepted with the limits below. Raw evidence retained at development `/home/linus/er26/logs/`; complete manifest SHA-256 `0b19825eba9780cfa439161e781e7993ef8b1b11fb3d80a755c0508407e7a215`; affected race log `2c848c92f9f98b243a421b7bec8db9e56ca0e59c0f37831f9a2bcbad6e2cd56b`; coverage profile `50ff400a805ba63a2e86104a1faf88fe1e6ce3c463eb5879af07d4848caf1f5f`. Parent rechecked raw manifest successfully.

## Limits and next gate

PG16 and full repository/container acceptance remain open. Real-artifact HTTPS delivery, actual update/rollback, accessibility/browser/keyboard and broader role/signing work are not closed. Fixture uses an actual verified webhook binary with a synthetic archive-pin marker; this is not archive-install integrity proof.

Inherited TestAdmissionRequiresProbe lacks a valid root, so its denial must not be counted as readiness proof. New valid-root deterministic test supplies the required admission predicate proof; repairing the redundant fixture is a follow-up. No arbitrary descendant-tree cleanup, plaintext erasure after SIGKILL, hostile same-UID defense or multi-controller guarantee is established.

No performance improvement claimed. Control-plane root scans, lifecycle waits and repeated validation are intentional costs; no filesystem scan is added to alert delivery. End-to-end latency impact is unmeasured and must not be described as negligible.

Development root remains97% inode-used; all generated validation source/data/cache was off root. Retained task cache319MB, source6.2MB and raw logs498KB; inactive exact task socket directory was cleaned. No unrelated cleanup. Forgejo checkpoint delivery only; GitHub distribution is outside this task.
