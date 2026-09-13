# Legacy mailbox adoption

ID: `v2.identity-provisioning.legacy-mailbox-adoption`

State: `in_progress`

Admit one existing email-keyed mailbox into manager-owned opaque SCIM state
through a redacted preview, exact confirmation digest, public
`gotth-scim.Reconciler`, and the existing serializable PostgreSQL projection.
The operation preserves mailbox data and credentials and does not manufacture
OIDC identity, session, or role authority.

Canonical state lives in `workflow.toml`. This folder holds scoped evidence,
review notes, and postmortems only.
