# v1 first plugin containers evidence

Date/time: 2026-07-16 01:50 CDT

Commit: 6456a60cb0a5d86ea2ceb4bf83d9ae5e8fa6f8bf

## Scope implemented

Implemented only `v1.mail-core.first-plugins`.

Added:

- first mechanism plugin definitions:
  - `external-webmail`
  - `manual-dns-export`
  - `manual-letsencrypt-cert`
  - `local-filesystem-backup`
- capability sets for each first plugin
- `cmd/gmf-plugin`, a small gRPC plugin runner using the existing v0 `PluginControl` protobuf/gRPC contract
- Docker build output for `/usr/local/bin/gmf-plugin`
- reference Compose services for all four plugin containers
- no Docker socket mounts
- local backup plugin gets only a named `/backup` volume

## Verification performed

Passed:

```text
go test ./...
```

Covered behavior:

- all first plugins exist with correct seams and non-empty capabilities
- authenticated direct capability checks succeed
- gRPC plugin health rejects wrong service token with `Unauthenticated`
- gRPC capability check succeeds with service identity metadata and deadline
- reference Compose includes all four plugin services
- reference Compose does not mount `/var/run/docker.sock`
- Dockerfile builds and copies `gmf-plugin`

## Known gaps / next increments

Still outside this child:

- seam-specific protobuf services beyond v0 `PluginControl`
- live plugin-to-core registration/persistence
- real DNS export, ACME issuance, backup write/verify, and webmail provider behavior
- end-to-end reference Compose runtime smoke

No accepted gap remains for the first plugin identity/container/control-contract surface implemented here.

## Next recommendation

Proceed to `v1.mail-core.diagnostics-smoke-snapshots`: aggregate doctor/debug/trace/queue/smoke/snapshot surfaces over the v1 primitives and record the remaining reference-smoke gap honestly if live Compose cannot be completed in this pass.
