# Real packaged webhook delivery checkpoint — 2026-09-26

Base: 9b34def6130dcdeb2653ff53f0ff491bf6c90ec6. Test equipment only; no production change.

## Proven mechanism

The independently pinned alpha.1 archive is verified before bounded parsing or execution; exact members/checksums, canonical manifest and metadata are checked. Actual manifest-derived grant/session identities bind the registered instance. Deployment-verified private staging is not a product downloader or runtime binary-rehash guarantee.

Real registration API → cookie/CSRF configuration preview/confirmation → readiness Test → Enable → packaged subprocess HTTPS/HMAC delivery → durable SQL result → Disable. Production runtimeMux and configureExtensionsFromEnv wire the real supervisor and SQL recorder; only login/session authority is a fixture. The independent receiver authenticates bounded exact wire bytes and expected JSON/header identities before204. Wrong HMAC produces403/permanent rejection; untrusted TLS receives zero HTTP calls and produces retryable failure. Disable removes runtime files and prevents a subsequent unique alert reaching the receiver.

Private bwrap user/PID/IPC/UTS/network namespaces, readonly host-root view, private tmpfs and standard CA path preserve the closed production child environment. No insecure TLS or host trust changes. This is trusted test equipment, not a hostile-code sandbox or exclusive one-CA trust-universe claim.

## Identity and verification

- Archive SHA256: 5cb6043ca200acfa67d4c6a85e0c1ba070c51dc550cacca7ce538021c8d9e83a
- Binary: 616d9fd3e99543f5dbfa92f526d51551b3883815881213fd7ba44338f4c83994
- Manifest: 0f515328c232f9c0db4d1e95be4877b7819815e5ade4cd6936ea823115d5c79e
- Final test source: 17a497f96e5d1b3590f844a86f9a8115238904749249e28759d78fb7b109ef5b
- Final runner: 3f89a307d70f4c7dd377135d785b8e6ed339c1d2ea715798ce08624eede7e81f
- Final changelog: d8929bbc3a9d03304b6ab3fb5ce49406b3e2d3f85de5efdc7b9ec1cbbc681281

On development: Go1.26.6, PostgreSQL16.14 (queried160014), bwrap0.11.2. Compile cmd/gotth-mail test binary with go test [-race] -p=2 -c; execute scripts/extensions-delivery-acceptance.sh TEST_BINARY ALPHA1_ARCHIVE PG16_BIN. Normal acceptance PASS1.47s; race PASS4.44s; both mandatory cases execute without skip. Full cmd/gotth-mail race suite PASS; its separate opt-in packaged-case skip is not credited as acceptance. Formatting, shell syntax and diff checks passed. No unchanged full-repository gate rerun.

Positive alert ce6dddfc-0d3d-4045-911a-dbe6379e5a4c / correlation3cd56b41-febf-4832-8d6f-b1de2a58f443: independent receiver body SHA256721bf783a9b0b59006587cbc4446c63b07ffd728de64584971e3e757c6a3e5ed, SQL delivered/receiver_accepted, https-webhook/hmac_sha256. Receiver boundary helper additionally covers65535/65536/65537/131072 bytes and malformed/wrong MACs; no exhaustive TLS or payload matrix claim.

Raw development evidence under /home/linus/.artifacts/gotth-mail-real-delivery-20260926:

- acceptance-final.log: 0afa4037263f95b58847a3eee88230ed97972a61f673315a17b5369ad21e2291
- acceptance-race.log: 7ecc45fb48bae5be703d225a58ef3da17c66043a142805052ec304d5f9c537d9
- cmd-package-race.log: 4623f33d8051b24ec67c0077fedca72e571fd6d521d966c5ab914be0716b32bc

Independent reviews9f967eac-2a4c-4435-9ef9-6d4af1e5570f and03b32d85-8549-4d4b-8f01-4597e87ed350 PASS. Executable source unchanged between reviews; second reviewed final documentation references. Parent verified hashes, complete fixture/runner, actual production wiring and raw results. Accepted only for this checkpoint.

## Resources and limits

Worker observed no live fixture processes at handoff. Namespace exits destroy private CA keys/PG/runtime data; runner independently verifies successful temporary cleanup. Exact inactive test binaries removed after hashing. Required source/logs retained:6,623,232 allocated bytes/644 entries; existing bounded caches reused. Development root inode count5,817,051/6,056,957 remained97%; no root-heavy work or unrelated cleanup. Performance N/A: no production behavior/cost change or speedup claim.

Mocked login, in-process Mail handlers; real packaged subprocess and receiver network. NOT native-browser, keyboard, accessibility, live Authentik, deployed-server, update/rollback, retry/exactly-once, beta or release admission. Those gates remain open. No workflow completion, tag, merge or deployment follows from this record.
