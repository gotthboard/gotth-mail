# Extensions administrator evidence — 2026-09-19

## Admission scope

This slice implements the repository-owned extension administration boundary:

- exact product/repository/artifact/manifest/grant/session inventory;
- closed, bounded host-rendered scalar metadata;
- AES-256-GCM write-only installation secrets with instance/slot AAD;
- durable actor/revision/expiry/single-use previews;
- capability, configuration-schema, configuration-value, and secret-slot diffs;
- authenticated test-before-enable and route-before-stop ordering through a
  narrow runtime interface;
- complete previous-version rollback state;
- separate confirmed secret deletion and uninstall;
- strict bearer API and durable OIDC-role plus CSRF browser admission;
- cross-product isolation and redacted audit persistence.

The feature does not claim a production supervisor. No independent
`gotth-extension-<slug>` artifact or documented configuration/secret transport
is present. Production creates the durable administrator only when a protected
master-key file is configured, but supplies no runtime adapter; test, enable,
and disable therefore fail closed. This is the exact remaining blocker.

## Verification evidence

Development host: `10.0.0.97`, worktree
`/tank/development/linus/gotth-mail-worktrees/v3.ops-import-admin.extension-management-ui`.

Focused real-PostgreSQL verification passed:

```text
GOMAXPROCS=2 go test -v -p=1 ./internal/extensionsadmin ./internal/httpui ./internal/store
GOMAXPROCS=2 go test -v -p=1 ./internal/authz ./internal/authn ./internal/httpui
GOMAXPROCS=2 go test -p=1 ./internal/api ./cmd/gotth-mail
```

The lifecycle test proves encrypted secret round-trip only into the runtime,
no plaintext projection/preview/audit persistence, wrong-confirmation
rejection, exact start/probe/stop test order, start/probe/admit enable order,
revoke/stop disable order, update diff persistence, complete rollback, separate
secret deletion/uninstall, stale-preview rejection, unhealthy/probe/revoke
failure isolation, and database-enforced product isolation.

The browser/API tests prove bearer denial, strict unknown-field JSON rejection,
Mail-owned markup, no secret rendering, durable OIDC global-admin admission,
and mutation CSRF rejection. SQL session tests prove roles are loaded from
durable `role_bindings`; token group claims remain non-authoritative.

`internal/extensionsadmin` statement coverage is 73.9%. The exercised surface
includes all user-visible lifecycle transitions and the critical failure-order
paths. Remaining uncovered statements are mostly injected entropy/database
serialization failures, corrupt-row defensive returns, and recovery branches
that require a failing database driver. That explicit gap is preferable to a
fake percentage built from mocks that cannot prove PostgreSQL behavior.

Final repository and integration gates passed on the development host:

```text
git diff --check
python3 -c 'import tomllib; tomllib.load(open("workflow.toml","rb"))'
GOMAXPROCS=4 go test -p=2 ./...
GOMAXPROCS=4 go test -race -p=2 ./...
GOMAXPROCS=4 go vet ./...
GOMAXPROCS=4 go build ./...
./scripts/containerized-mailu-import-smoke.sh
./scripts/containerized-outbound-policy-smoke.sh
./scripts/containerized-notification-plugin-smoke.sh
./scripts/containerized-webmail-imap-smoke.sh
./scripts/containerized-webmail-smtp-smoke.sh
./scripts/containerized-webmail-runtime-smoke.sh
./scripts/containerized-webmail-ui-smoke.sh
./scripts/reference-runtime-smoke.sh
```

The detached System V shared-memory count was `4084` before the focused
PostgreSQL test and remained `4084` after the complete normal/race/container
run. The test harness no longer strands new PostgreSQL segments.

The first reference-runtime run proved SMTP rejection/acceptance, alias
delivery, DKIM, Dovecot IMAP, Roundcube, and plugin health, then exposed two
stale final shell assertions that still expected raw recipient addresses in
policy logs. The runtime intentionally emits correlation ID, decision, and
reason without those addresses. The smoke now asserts
`decision=ok reason=alias_expanded` and
`decision=not_found reason=recipient_not_found`, preserving the behavioral
proof without weakening log privacy.
