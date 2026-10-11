# Implementation specification: role-binding operator

## Operator API

Add `internal/rolebinding`:

```go
type Request struct {
    Operation string
    Issuer string
    Subject string
    Mailbox string
    Role string
    Domain string
}

type Plan struct {
    PlanID string
    IdentityID string
    Mailbox string
    Role string
    Domain string
    Operation string
}

type Result struct { Plan Plan; Changed bool }

type Service struct { DB *sql.DB; Now func() time.Time; Entropy io.Reader }
func (Service) Preview(context.Context, Request) (Plan, error)
func (Service) Apply(context.Context, Request, confirmation string) (Result, error)
```

The CLI grammar is fixed and rejects duplicate/unknown values through existing
flag parsing plus request validation. `--domain` is forbidden for
`global_admin` and required for the other roles. Output is JSON.

## SQL

Preview uses bounded indexed equality queries. Apply starts
`sql.LevelSerializable`, locks the identity, target domain, and existing
binding rows, recomputes the canonical plan, compares a 32-byte hexadecimal
digest in constant time, then performs one exact `INSERT` or `DELETE`.

Grant requires an enabled mailbox and enabled mailbox/target domains. Revoke
requires the exact identity and domain to remain identifiable but may remove a
binding after either has been disabled. The implementation must distinguish
not-found, ambiguity, inconsistent stored state, and stale confirmation with
fixed bounded errors.

## Migration

Add `migrations/0018_role_binding_authority.sql`, the matching immutable string
and registration in `internal/store`, and parity tests. Before adding
constraints, use explicit `DO` checks that raise if inconsistent or duplicate
logical rows exist. Never delete or rewrite existing authority implicitly.

## Planned Group-origin compatibility

When the Group projection child is activated, replace the direct INSERT/DELETE
choice with operator-owned origin grant/revoke and conditional orphan cleanup.
Keep existing CLI flags. Group INSERTs explicitly set operator_owned=false;
operator INSERTs and the legacy default remain true. Retain 0018 uniqueness.
Grant on a Group-only row is a real ownership mutation, not unchanged. Revoke
with no operator origin is no-op, not an assertion that effective access vanished.
Preview/result/audit add operator origin, Group-source count and effective_after.
Digest v2 binds request/identity/domain, operator state, binding UUID/revision and
sorted source mapping IDs/revisions; old/stale confirmations reject. Origin,
revision and redacted success audit share the SERIALIZABLE transaction. Other
origins/UUIDs survive; no-op does not churn rows/audit. Required tests cover two
Groups plus operator, each removal, audit rollback and concurrent absent rows.
The [v2 recovery contract](../../../../docs/implementation/v2-identity-provisioning.md#fence-and-rollback-future-deployment-authority-required)
fences old CLIs/readers/writers; this identity CLI currently does not run ledger
validation. DEFAULT TRUE alone is not rolling compatibility. No migration number
is assigned by this amendment and no prior evidence is rewritten.

## Verification

PostgreSQL tests create one SCIM-backed mailbox, verified identity, and active
session. They cover all roles, global/scoped domain rules, grant/revoke/no-op,
wrong issuer/subject/mailbox, disabled state, duplicate constraints,
confirmation mismatch, stale preview, concurrent grants, injected audit
failure rollback, existing-session authorization change, restart persistence,
and bounded JSON/audit output.

CLI tests must execute preview and apply against PostgreSQL and prove the
database changed only after exact confirmation. Full normal/race/vet/build and
container migration gates remain required.
