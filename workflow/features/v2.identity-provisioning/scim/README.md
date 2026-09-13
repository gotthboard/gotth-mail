# SCIM v2 provisioning API

ID: `v2.identity-provisioning.scim`

State: `in_progress`

Current contract: replace the handwritten SCIM router with the exact pinned
`gotth-scim` server plus a conformant transactional PostgreSQL adapter and
atomic mailbox/password/audit projection. Email addresses are not resource IDs.

Current implementation on the feature branch provides that server and SQL
adapter, opaque resource IDs, ordered indexes, permanent tombstones,
write-only password projection, fail-closed runtime routing, restart rebuild,
and explicit unsupported Groups behavior. It is not complete until full/race
verification, cold review, admission into the unfinished 1.0-alpha line, live
Authentik lifecycle proof, and backup/restore proof are recorded. Legacy
email-keyed adoption also remains an explicit operator-controlled migration.

Canonical state lives in `workflow.toml`. This folder holds scoped evidence, review notes, and postmortems only.
