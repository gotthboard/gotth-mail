# Update confirmation and PostgreSQL16 checkpoint — 2026-09-26

## Native update form repair

Base: b749d0de3f95cf58a9f432a43678d4dde5e74edc. The repair separates required target-entry controls from the confirmation form and displays the four validated target identifiers. Mutation still uses the actor/revision/expiry-bound stored preview; no new authority or endpoint.

Test-first corrected suite: only the actual native-success case was red, with fourteen other cases passing. Initial fixture-only unique-ID and routed-implies-enabled violations were corrected without weakening assertions; their failed logs remain retained. Repaired fifteen-case full-route suite passed with race detection on PostgreSQL16.14; SQL test asserts server_version_num160014. Whole HTTP UI package race/coverage PASS78.298s62.9%; scoped vet exit0. applyExtensionUIAction overall57.1% coverage includes unrelated action branches; this is not a100% function/package claim.

Chromium151.0.7922.71, default sandbox: actual captured old form remained invalid after confirmation and submitted zero times. Repaired form became valid and submitted once, with exactly action/confirmation/csrf_token/preview_id. Test-only appended instrumentation observes native checkValidity/button click and intercepts navigation; it is not a live authenticated browser network POST, complete no-JavaScript lifecycle, keyboard or accessibility proof. The independent routed HTTP suite proves service mutation.

Independent cold passes6f8e4476-84b0-4108-a83c-8cc31de16234 and97031da9-17d2-422b-9481-2993702610af verified the frozen four-file candidate. Parent admits this checkpoint with these limits. Source/test SHA256:

- extensions.go:32cda16f4fed3d753f365eaad6e1c22cfbbb987cdcc47ebc5d72877ac156e0f3
- extensions_update_test.go:c3b21962c9aaedc3901925ed69e815fdc2cd88f5a16faed4fb2f490703a2e2c4

Raw development evidence: /home/linus/.artifacts/gotth-mail-update-confirmation-20260926/logs/.

- red3.log:ff1fb73fe7bf0eb8aeaec079a5bc58642dc6ed757d1f0fdda434962af6c68fe1
- green.log:66f0803597d7e61939e338d84e30910f00c9f94101c75d5b54de7a71086ec6bf
- ui-package-race.log:32bedfac7ddda54aaea43e604759f0047508a0f4dad1654466821bce36640ad9
- ui-coverage.out:c777dc6388558d1cfdd17c47205b52c3e0df7e959b0c7fea12d31c2944487a4b
- browser-native-proof.json:b2299f4770527748eb780e41daa45220044dec0cc28563255f8f474bf0fc13aa

Focused SSH command deadline expired during cold compilation/testing, but inspection established the remote test completed exit0 with its full PASS log and no surviving process. It was not blindly rerun.

## Recovery checkpoint cross-version verification

The unchanged recovery snapshot at b749d0d separately passed all five affected packages on native PostgreSQL16.14 with Go1.26.6, -json -p=2 -count=1 -race -coverprofile. Twelve source hashes matched before/after. Results: runtime2.048s76.2%; administrator378.659s76.6%; UI38.413s60.6%; API539.469s65.4%; command282.050s69.9%. This run excludes the subsequent update-form patch, whose own UI gate is above.

Real webhook lifecycle, abrupt parent death, Health/admission interleaving, recovery UI and seeded blocked-runtime/Postfix-listener isolation all explicitly PASS. Two optional API tests skipped: TestLiveContainerWebmailShellReachable and TestWebmailBrowserFixture. Neither is credited as container/browser acceptance. Raw development /home/linus/er26/logs/pg16-race.jsonl SHA256d9573055abe340063d02f4d48d843655bf56e2aa23bd58be14bba82d16b8a9b5; coverage8828a786f597fe8481d52cc8f05c8cc99bf7035f0b577b04c865cadf385e0f05; summary558ffe2d00b9a4e5ddd745bf6ec5b7e3c5043bc2b650d6b9d0d0d4e6678b6b95. Previously proved scoped vet on the identical recovery source remains credited.

PG16 was built from official16.14 source SHA256f6d077142737920858ce958ccdb75c6ee137a63b5b0853c70693d401ac7e3471 into task-owned ZFS storage, not system directories. Tool versions and an isolated SQL160014/transaction/clean-shutdown smoke were independently recorded. This is native SQL/runtime evidence, not Alpine container-image equivalence.

## Bounds and remaining work

No speedup claim or new SQL/runtime round trip. Display retains existing bounded validated input; formatting-cost effects are not benchmarked. Required source/logs retained; reusable UI cache237MB and recovery cache319MB remain off root. Only exact inactive browser profiles, private socket remnants and stopped disposable PG smoke database were removed, with path-level inventory. Development root remains97% inode-used; unrelated cleanup forbidden.

Real packaged-extension successful HTTPS delivery, full setup/update/rollback lifecycle, complete accessibility/browser matrix, signing/role completeness and full beta gates remain open. Neither this checkpoint nor two scoped PASS reviews mark the feature, beta, release or deployment complete. Forgejo-only delivery; no tag or production change.
