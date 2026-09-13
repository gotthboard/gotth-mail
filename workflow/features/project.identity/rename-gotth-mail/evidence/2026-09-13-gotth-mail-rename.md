# GOTTH Mail rename evidence — 2026-09-13

Status: canonical Forgejo rename and ownership transfer complete; public GitHub
distribution blocked.

## Canonical state

- Forgejo repository ID: `46`
- Canonical repository: `gotthboard/gotth-mail`
- Canonical URL: `https://git.dannyhunn.com/gotthboard/gotth-mail`
- Canonical SSH remote: `forgejo:gotthboard/gotth-mail.git`
- admitted `main`: `fb1fcb893bf47aa00014c1a55b156603d463eb9a`
- verified renamed unfinished v2-v5 implementation parent:
  `26b20599fac8a8ca612259d2ea00d327777878b1`
- Forgejo PRs #3 and #4 fast-forwarded the main-only rename and final evidence
  without importing unfinished v2-v5 code.

The repository remains private and the authenticated operator retains admin,
push, and pull permissions. Existing tags and commit history were not rewritten.

## Verification

Both the main-only rename and the renamed unfinished development line passed on
the development host:

- `git diff --check`
- shell syntax for every repository script
- `go test -count=1 ./...`
- `go test -race -count=1 ./...`
- `go vet ./...`
- builds of `gotth-mail`, `gotth-mailctl`, and `gotth-mail-plugin`
- `docker compose -f compose/reference/docker-compose.yml config`
- deterministic regeneration of protobuf Go and gRPC bindings
- current-name audit excluding the rename contract and immutable historical
  changelog, evidence, review, event, commit, and tag records

The first development-line full run exposed an invalid `X-GOTTH Mail-*` header
introduced by mechanical replacement. The canonical token is
`X-GOTTH-Mail-*`; the signer, verifier, and adversarial tests were corrected,
and both full suites then passed.

## Former-path behavior

The Forgejo API returns `301` for the former `linus/GopherMailForge` and
intermediate `linus/gotth-mail` paths. SSH Git access to those obsolete paths
fails closed; it does not redirect across the ownership transfer. Canonical
development checkouts were moved to `/tank/development/linus/gotth-mail`, their
linked worktrees were repaired, and their remotes now use the canonical SSH
URL.

## Blocking distribution gap

`https://github.com/gotthboard/gotth-mail` does not exist or is inaccessible,
this host has no authenticated GitHub CLI/API session, and Forgejo reports no
push mirror for the repository. The binding GOTTH repository policy requires a
matching public GitHub distribution mirror. Therefore `project.identity` and
`project.identity.rename-gotth-mail` remain `blocked`; the Forgejo rename is
complete, but full project-series admission is not represented as done.

No production mail deployment, external email, or Telegram API call occurred.
