# v0 Foundation implementation evidence

Date/time: 2026-07-14 23:50 CDT; admission-fix update 2026-07-16 01:23 CDT

Commit: current commit; hash assigned by Git after commit

## Scope implemented

Implemented the v0 foundation only. No v1 mail-daemon production behavior, no SCIM provisioning, no full OIDC login, no real plugin implementations, and no custom webmail were added.

Implemented artifacts:

- Go module and command skeletons:
  - `cmd/gophermailforge`
  - `cmd/gmf`
- HTTP/API shell:
  - health/readiness/status endpoints
  - authz explain endpoint
  - required v0 config effective/render/diff/apply endpoints
  - audit event listing endpoint
  - plugin list and plugin health endpoints
- GOTTH-compatible server-rendered UI shell.
- Typed config parser/validator for the v0 YAML shape using a real YAML decoder with known-field rejection.
- TLS validation including production rejection of `dev_self_signed` and manual cert/key requirements.
- Authentik base model and bootstrap/recovery boundary that does not depend on Authentik health.
- Deterministic render output with generated-file headers.
- File-backed staged render output, current-applied marker, and diff/apply gate requiring explicit operator-provided staged ID confirmation.
- Audit writer with recursive redaction plus SQL audit persistence for source IP/user-agent and redacted before/after payloads.
- Static v0 authorization simulator for local admin, break-glass, API token, plugin service, and placeholder identity actors.
- Initial schema/migration representation, empty-schema migration runner, embedded Postgres SQL migration execution tests, and database-enforced enum/status/seam/credential constraints where enforceable in v0.
- Plugin registry/control skeleton with authenticated health/version/capability checks, failure isolation behavior, generated protobuf/gRPC bindings, metadata/deadline enforcement, canonical status codes, and gRPC bufconn transport tests.
- Protobuf contract file and generated Go bindings for `PluginControl` health/version/capability RPCs.
- Dockerfile and reference Compose skeleton including database and required Authentik service/profile.
- Contract fixtures and tests.

## Verification performed

Passed:

```text
go test ./...
go build -o /tmp/gmf-v0 ./cmd/gmf
go build -o /tmp/gophermailforge-v0 ./cmd/gophermailforge
/tmp/gmf-v0 config --config test/contract/sample-config.yaml
/tmp/gmf-v0 render --config test/contract/sample-config.yaml
/tmp/gmf-v0 diff --config test/contract/sample-config.yaml
/tmp/gmf-v0 apply --config test/contract/sample-config.yaml --confirm <staged-id>
/tmp/gmf-v0 migrate
/tmp/gmf-v0 authz
git diff --check -- .
```

Passed with Docker socket access through sudo:

```text
sudo docker build -t gophermailforge:v0-smoke .
```

The container build ran `go test ./...` inside the build stage and produced the `gophermailforge:v0-smoke` image.

## Coverage notes

Relevant v0 behavior has tests for:

- config parser success/failure paths
- unknown top-level and nested plugin config rejection
- production-dangerous TLS rejection
- plugin seam validation
- generated/override directory overlap rejection
- deterministic render output
- generated-file headers
- diff output
- CLI render writes staged output
- CLI apply rejects missing/wrong confirmation and accepts the matching staged ID
- apply confirmation and audit emission
- audit redaction
- authz allow/deny explanations
- Authentik config validation and bootstrap availability during Authentik outage
- empty migration run plus embedded Postgres schema execution, migration-history count, unique constraint, foreign-key rejection, enum/check constraints, plugin credential constraints, and SQL audit persistence
- domain/token/plugin registration validation helpers
- authenticated plugin control success through local and generated-protobuf gRPC bufconn paths
- unauthenticated, missing correlation, and missing deadline rejection through canonical gRPC status codes
- disabled/malformed plugin failure isolation
- HTTP health/readiness/status shell plus required v0 config/audit/plugin API shell routes
- required v0 artifacts, Compose Authentik presence, no Docker socket mount, and proto RPC definitions

Known gap:

- No accepted v0 verification gap remains.

## Next recommendation

v0 is ready as the foundation baseline. Start v1 only after review of this commit, because v1 should build on the daemon-facing contracts without smuggling mail-stack behavior back into v0.
