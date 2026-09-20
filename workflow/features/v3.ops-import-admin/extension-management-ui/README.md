# Extensions administrator

State: `in_progress`

Host-owned GOTTH Mail administrator for extension inventory,
configuration, write-only secrets, permissions, health, enable/disable,
updates, audit, versions, and rollback.

It depends on admitted `gotth-extensions` consumer conformance. Extensions may
not inject presentation or receive Mail administrator authority.

The repository-local administrator is implemented and verified: durable
inventory, encrypted write-only secrets, actor/revision-bound previews,
host-owned API/UI, durable OIDC-role plus CSRF admission, runtime ordering,
update diffs, full-version rollback, and separate secret deletion/uninstall.

The production adapter is now implemented for the exact non-Telegram
`gotth.mail.notification.webhook` contract. It verifies a digest-named local
artifact, projects configuration and the HMAC key through owner-only files,
supervises the process group, authenticates a Unix gRPC transport, validates
the complete foundation handshake and health, admits/revokes alert routing,
and removes runtime secrets only after confirmed stop. Static notification
configuration conflicts fail startup rather than silently changing routing.

The feature has resumed at its only remaining boundary: distribution
admission. The canonical private Forgejo `gotth-extension-webhook` repository
and real cross-process lifecycle exist, but the required public GitHub
repository, one-way mirror, immutable extension tag/artifact, and
Forgejo/GitHub release parity do not yet exist. Production install/enable
remains closed until those exact public artifact identities are published and
pinned. Telegram is explicitly outside this resumed work.
