# Opaque SCIM Groups

ID: `v2.identity-provisioning.opaque-scim-groups`

State: `done`

Enable the pinned `gotth-scim` Group protocol surface while enforcing that
every member is a live opaque User ID in the same provisioning scope. Persist
normalized membership atomically and grant no role authority until the live
Authentik profile and explicit Group-to-role mapping are separately admitted.

Canonical state lives in `workflow.toml`. This folder holds scoped evidence,
review notes, and postmortems only.
