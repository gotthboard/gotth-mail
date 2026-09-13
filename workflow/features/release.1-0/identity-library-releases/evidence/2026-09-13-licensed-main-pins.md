# Licensed GOTTH identity-library main pins — 2026-09-13

## Scope

Update GOTTH Mail's unfinished development line from the previously reviewed
unlicensed library revisions to the exact MIT-admitted `main` revisions. This
does not implement the consumer adapters, admit library tags, publish a GOTTH
Mail release, merge unfinished work into `main`, or deploy anything.

## Exact inputs

- `github.com/gotthboard/gotth-oidc`
  `v0.0.0-20260913195135-1ae119e52f8e`, resolving to
  `1ae119e52f8efc3392fcc9fa716b1b27c9ffce6c`, module checksum
  `h1:bHA7DSBvBEU0CkTBIPQYrdQIoEAZ9ulvBlm794hOt48=`;
- `github.com/gotthboard/gotth-scim`
  `v0.0.0-20260913195137-255629e27f7d`, resolving to
  `255629e27f7df301d263a116fb37fd315ff54693`, module checksum
  `h1:Bl9nYpMvRiMm58P3JmH/lV0Vmgm5rpvkrXZV0PaqbkU=`.

The canonical Forgejo and public GitHub `main` refs were independently checked
for exact commit parity before these pins were admitted.

## Verification

- `git diff --check`;
- focused external-consumer contract tests;
- full and race test suites;
- `go vet ./...`;
- builds of `gotth-mail`, `gotth-mailctl`, and `gotth-mail-plugin`;
- exact `go list -m` module-version assertions, run separately from the
  repository audit;
- canonical Forgejo/public GitHub main-ref assertions, also run separately;
  and
- the generic repository manifest/path audit failed on the pre-existing
  missing source path `proto/gotth/mail/notification/v1`. This pin-only change
  does not repair that unrelated defect and does not claim the generic audit
  passed.

## Remaining blocker

The OIDC protected-attempt/session adapter, transactional SCIM store and
projection adapter, opaque-ID migration, and live Authentik lifecycle proofs
remain unaccepted. The library release contracts therefore still block tags.
MIT admission and exact pins do not manufacture consumer acceptance.
