# Durable role-binding operator

This feature supplies the missing operator boundary between a verified,
SCIM-backed OIDC identity and GOTTH Mail's durable `role_bindings` table.

Contracts:

- [PRD](prd.md)
- [architecture](architecture.md)
- [implementation specification](implementation-spec.md)

It does not trust Authentik group claims, create identities, bypass SCIM, or
write role rows through ad hoc SQL.
