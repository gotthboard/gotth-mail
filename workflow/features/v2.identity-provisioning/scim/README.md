# SCIM v2 provisioning API

ID: `v2.identity-provisioning.scim`

State: `in_progress`

Current contract: replace the handwritten SCIM router with the exact pinned
`gotth-scim` server plus a conformant transactional PostgreSQL adapter and
atomic mailbox/password/audit projection. Email addresses are not resource IDs.

Canonical state lives in `workflow.toml`. This folder holds scoped evidence, review notes, and postmortems only.
