# Architecture: role-binding operator

## Boundary

`internal/rolebinding` owns one narrow database operation. The CLI is its only
operator entry point. It receives public identity identifiers and policy
values, not credentials. There is no generic SQL, table, column, predicate, or
authorization-expression input.

Preview and apply share one canonical request normalizer and one state loader.
The loader joins `identity_refs`, `mailboxes`, and `domains`, verifies the
exact Authentik issuer/subject/mailbox tuple, resolves an optional target
domain, then observes one logical binding. Apply repeats the same load under
row locks in a serializable transaction before comparing the confirmation.

## Database contract

Migration `0018_role_binding_authority` adds:

- a check requiring `global_admin` to have NULL `domain_id` and both scoped
  roles to have a non-NULL `domain_id`;
- one unique partial index for identity/global role; and
- one unique partial index for identity/scoped role/domain.

The migration must first reject inconsistent or duplicate existing rows. It
does not silently repair policy. The current reviewed development line has no
production writer, so unexpected rows are evidence of manual mutation and
must block migration rather than be guessed away.

## Confirmation and audit

The plan digest covers a versioned domain separator, normalized request,
resolved identity UUID, resolved domain UUID or absence, effective operation,
and the exact existing binding UUID/timestamp or absence. It contains no
session cookie, token, secret, verifier, or raw database error.

Apply inserts a random UUID or deletes the exact observed row, then records
`identity.role_binding.grant` or `identity.role_binding.revoke` with local CLI
actor, identity resource, role/domain, and no mailbox/subject/issuer in the
redacted payload. An unchanged plan commits nothing and writes no audit.

## Planned origin-aware extension

The [v2 Group projection contract](../../../../docs/implementation/v2-identity-provisioning.md#durable-group-to-role-projection-planned)
supersedes direct effective-row deletion when Group origins exist. Keep one
unique effective binding with operator_owned and per-mapping origins; Apply
changes operator ownership and removes only an orphan row. Origin changes and
redacted audit/revision updates commit together. This preserves other grants
and binding UUID, without making Group projection an operator-service caller.
Current-issuer/local-enabled guards apply only to Group origins. Existing
operator semantics are not silently narrowed by issuer-file absence/change.

## Runtime projection

`authn.SQLStore.BoundSession` already queries `role_bindings` for every bound
session load. Tests shall use an existing session before and after grant and
revoke to prove privilege changes are immediate and survive service restart.
No session contents are rewritten and no ID-token group claim is consulted.
