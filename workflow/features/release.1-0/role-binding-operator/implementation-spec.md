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
