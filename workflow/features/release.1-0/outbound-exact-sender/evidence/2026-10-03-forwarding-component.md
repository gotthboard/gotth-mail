# F3 forwarding component — scoped admission

2026-10-03. Two fresh independent revision2 reviews PASS; parent reconciled both and admits F3 only. No mandatory component finding remains. This supersedes earlier pending-review wording, not the preserved initial FAILs.

Base c3654450a2dbe193b6e3cb745aded5e295db5ced, branch workflow/feature/release.1-0.outbound-exact-sender. Tested executable snapshot 1ba147d579207f1eb051b4c85d1beaaafd7c2c8e5501b08ddbee1b51c78b96af. Forwarding helper SHA256 7fb8571d0899aaf9ba2fb374ec617b0d69c7744acec88926843642c5344ae7bc; runtime loader d6334e9f7d087d5f1208de4bab5ed114386f01ec3f483883d197929b1fd327e7.

Explicit local identity is resolved, opaque captured bytes attached as base64 original.eml, and a new local wrapper signed and independently verified. Local Message-ID grammar rejects malformed IDs. The loader preserves raw binary key bytes; deterministic synthetic single/duplicate regressions prove the repaired whitespace-tail failure. No SMTP or caller authorization is performed by this component.

New execution: webmail normal8.259s/race28.347s; notification email family normal1.195s/race2.515s; both-package vet passed. Seven SQL tests excluded, three live tests skipped; notification tests are21 email cases, not the whole package. Build coverage95.7%, ID validator100%, loader83.3%; documented old failure branches and non-failing buffer returns remain uncovered. The documentation closeout reuses these checks with unchanged executable inputs; no new build or rerun is claimed.

Input19,156,674B/output27,525,120B bounds do not cover global50MiB forwarding. Boundary diagnostic allocation is approximately160.52MB/op, not RSS or concurrency admission. Conservative retained516MiB exceeded the512MiB planning target; allowance accounting542MiB is not measured peak. Historical variance is retained. Parent revised only remaining review/closeout planning to560MiB, not physical limits or execution authority.

Raw proof, original failures, historical manifests, both fresh reviews and source bridge are retained in workspace .artifacts/gotth-mail-beta-resume-20261003/signing-implementation/revision-2. Final candidate manifest f35be79bac58aefeecf95776d6d08b90f2ed1fce7afb635bdfb6e8fe79549094; original11 entries were checked before this docs-only closeout and changed documents preserved separately.

OPEN: actual forwarding authority/capture/caller wiring, ordinary submission, DSN/system provenance, native retries and full-size resource acceptance. Separate notification binary-loader concern remains unmodified/unreproduced and needs its own bounded follow-up. Workflow stays in_progress; no B5/beta, commit, publication or deployment admission.
