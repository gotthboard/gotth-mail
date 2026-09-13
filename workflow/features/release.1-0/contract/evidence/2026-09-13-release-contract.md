# 1.0 release-contract evidence — 2026-09-13

## Admitted boundary

- Stable GOTTH Mail is exactly `1.0.0` and requires the complete deployed
  stack plus owner acceptance.
- Every published pre-stable build is `1.0.0-alpha.N` or
  `1.0.0-beta.N`. Alpha means incomplete integration; beta means
  feature-complete hardening and acceptance.
- Historical `v0.*` through `v5.*` identifiers remain capability and evidence
  keys. They are not product versions, and history was not rewritten.
- The CLI, control-plane status API, and plugin Version RPC use one linked
  release identity. Invalid `0.x`, `v`-prefixed, zero-sequence, RC, later patch,
  or later-major build strings fail closed.

## Verification

Implementation parent: `200419a0a7d1e91a5ae6a2aaf01efba18214e2a0`.

On the development host, from the isolated
`/tank/development/linus/gotth-mail-worktrees/project.release-contract`
worktree:

- `go test -count=1 ./...` passed;
- `go test -race -count=1 ./...` passed;
- `go vet ./...` passed;
- all three commands built with linked version `1.0.0-alpha.1`;
- `gotth-mailctl version` returned exactly `1.0.0-alpha.1`;
- an `1.0.0-rc.1` plugin build was rejected before serving;
- every repository shell script passed `sh -n`;
- reference Compose rendering passed;
- TOML parse, unique-ID, and workflow-path checks passed with eight roots and
  thirty-four features; and
- `git diff --check` passed.

No tag, release artifact, deployment, mail, identity-provider state, database,
or production configuration changed.
