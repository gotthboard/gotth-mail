# Opaque SCIM Groups evidence — 2026-09-13

## Admitted mechanism

- GOTTH Mail exposes the pinned `gotth-scim` User and Group definitions. The
  library owns discovery, resource schemas, canonical validation, opaque IDs,
  ETags, filtering, pagination, replacement, and PATCH behavior.
- The product PostgreSQL adapter decodes the library's canonical Group record
  and accepts only distinct live opaque User IDs in the same storage scope.
  Missing users, cross-scope users, nested Groups, malformed members, and
  duplicate members fail closed.
- Migration `0007_scim_group_members` stores normalized membership with
  composite foreign keys that enforce scope and exact `Group`/`User` resource
  types. Group deletion cascades edges. User deletion is restricted while an
  edge exists.
- Group canonical data, normalized edges, and the redacted audit event commit
  in one transaction. An audit failure rolls back both resource and edges.
- Group membership is provisioning inventory only. No OIDC group claim is
  trusted and no `role_bindings` row is created by Group operations.

## Review repairs

The first real PostgreSQL run at `b7023dd26b7fab1e7d49e5a16b7ad97753984361`
found that referenced User deletion rolled back safely but surfaced as generic
HTTP 500. Commit `a74ad3eaf988556fa93d2db36c132639aac1eb82`
added an exact pre-projection conflict and safe concurrent foreign-key error
translation. Commit `772bf08716aed3c9f47aab771482f97eaa784da1`
then proved the database itself rejects cross-scope and wrong-resource-type
edges.

## Verification

Development host, runtime head
`a74ad3eaf988556fa93d2db36c132639aac1eb82`:

- focused store, SCIM adapter, and API PostgreSQL tests twice: pass
- full `go test ./...`: pass
- full `go test -race ./...`: pass
- `go vet ./...`: pass
- `gotth-mail`, `gotth-mailctl`, and `gotth-mail-plugin` builds: pass
- `go mod verify`: pass
- `git diff --check`: pass

Development host, final test head
`772bf08716aed3c9f47aab771482f97eaa784da1`:

- exact Group lifecycle and database-integrity test twice: pass
- cross-package store/SCIM/API coverage run: pass, 70.0% aggregate
- `replaceGroupMembers`: 80.4%
- `scimAction`: 100.0%
- `mapStoreError`: 83.3%

The unexercised membership-projector lines are defensive row scanning, close,
and driver-failure paths. The consequential protocol validation, referential
integrity, isolation, delete conflict, atomic rollback, and authority boundary
are exercised against PostgreSQL.

## Code graph

Graphify 0.9.32 extracted the code-only tree at the final test head:

- 1,805 nodes
- 4,472 edges
- 75 communities
- graph SHA-256:
  `1d52d9d1b75218c2c845f0de6e818a987c57e7231c436e5e7589aa988dbe4313`
- three potential secret fixtures were skipped; seven SQL files were omitted
  by the optional SQL parser and instead exercised by PostgreSQL tests

The graph artifact remains outside Git under
`/home/linus/.cache/openclaw-graphify/gotth-mail-opaque-groups-20260913-1838`.

## Remaining boundary

This closes non-authoritative SCIM Group storage only. The renamed live
`gotth-mail` Authentik issuer/profile, browser/passkey login, installed-provider
provision/disable/delete/Group lifecycle, exact stable Group-to-role mapping,
identity-aware backup/restore proof, GitHub mirror, tags, deployment, beta, and
stable 1.0 remain open. Product `main` was not touched.
