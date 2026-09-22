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
admission. Canonical Forgejo and public GitHub now advertise the same annotated
`v1.0.0-alpha.1` tag object and the same peeled tested commit. Two independent
builds produced the same Linux/amd64 archive SHA-256. Release objects and
uploaded archive/checksum parity have not yet been proved, so production
install/enable remains closed until those exact public artifact identities are
published and pinned. Telegram is explicitly outside this resumed work.
