# PRD: durable identity role binding

## Problem

GOTTH Mail resolves authorization from durable `role_bindings`, but production
code cannot create or revoke those rows. Tests insert them directly. That
leaves the first administrator impossible to admit without manual SQL and
makes the documented role projection incomplete.

## Required behavior

`gotth-mailctl identity role-binding preview|apply` shall grant or revoke one
role for one already-verified Authentik identity selected by exact issuer,
subject, and bound mailbox. The operator supplies:

- `--operation grant|revoke`;
- `--issuer`, `--subject`, and `--mailbox`;
- `--role global_admin|domain_manager|scoped_domain_access`; and
- `--domain` only for a domain-scoped role.

Preview is read-only and returns a deterministic confirmation digest plus
bounded identifiers and the effective operation (`grant`, `revoke`, or
`unchanged`). Apply recomputes the plan inside a serializable transaction,
requires constant-time digest equality, performs at most one role-row change,
writes one redacted success audit in the same transaction, and commits.

## Rules

- The identity must already exist as provider `authentik` and must resolve to
  exactly the supplied issuer, subject, active mailbox, and enabled domain.
- Global administrator bindings have no domain.
- Domain manager and scoped-domain-access bindings require one existing domain.
- Duplicate logical bindings are impossible in PostgreSQL, including the
  NULL-domain global role case.
- Grant/revoke retries converge without duplicate audit or row churn.
- Stale previews, conflicting identity selection, invalid roles/domains,
  disabled mailbox/domain, database errors, and audit failure reject without
  partial state.
- Existing sessions load roles from PostgreSQL for each authorized request;
  grants and revocations therefore take effect without minting a new session.
- OIDC token groups and SCIM Group display names remain non-authoritative.

## Exclusions

This feature does not create SCIM Users, create OIDC identities, infer roles
from email addresses or groups, bulk-map users, grant extension authority,
mutate a live database during repository verification, or expose a browser
role editor.

## Admission

Admission requires migration parity, PostgreSQL integration tests for every
role and state transition, stale-plan/concurrency/audit-rollback proofs, CLI
end-to-end tests, existing-session authorization projection, restart
persistence, full/race/vet/build gates, and two clean cold reviews.
