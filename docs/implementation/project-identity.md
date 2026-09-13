# GOTTH Mail project identity implementation

## Required changes

1. Move command source directories to `cmd/gotth-mail`,
   `cmd/gotth-mailctl`, and `cmd/gotth-mail-plugin`.
2. Change the Go module and every first-party import to
   `forgejo/gotthboard/gotth-mail`.
3. Move protobuf sources and generated bindings to
   `proto/gotth/mail/plugin/v1`, change the package to
   `gotth.mail.plugin.v1`, and regenerate both Go binding files.
4. Rename first-party environment variables, cookies, plugin metadata,
   generated configuration names, container services, fixture identities,
   and temporary artifact prefixes.
5. Update current PRDs, architecture, implementation specs, reference docs,
   workflow manifest, coverage map, tests, and scripts.
6. Preserve dated evidence, old changelog entries, workflow events, commits,
   and tags; append a new rename record instead of rewriting history.
7. Push the reviewed rename branch, admit it to `main`, rename and transfer the
   Forgejo repository, then verify refs and redirects.

## Verification

- `git diff --check`
- `gofmt` on changed Go sources
- regenerated protobuf output matches the renamed `.proto`
- `go test ./...`
- builds of all three renamed commands
- current-name audit excluding declared historical records
- Forgejo API and SSH ref parity before and after transfer
- old Forgejo URL redirect proof
- GitHub distribution parity, or an explicit blocker if credentials or the
  destination repository do not exist

