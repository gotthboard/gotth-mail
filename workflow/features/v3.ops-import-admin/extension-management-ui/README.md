# Extensions administrator

State: `blocked`

Host-owned GOTTH Mail administrator for extension inventory,
configuration, write-only secrets, permissions, health, enable/disable,
updates, audit, versions, and rollback.

It depends on admitted `gotth-extensions` consumer conformance. Extensions may
not inject presentation or receive Mail administrator authority.

The repository-local administrator is implemented and verified: durable
inventory, encrypted write-only secrets, actor/revision-bound previews,
host-owned API/UI, durable OIDC-role plus CSRF admission, runtime ordering,
update diffs, full-version rollback, and separate secret deletion/uninstall.

The feature is blocked at the honest production boundary. The repository does
not contain or pin an independently distributed `gotth-extension-<slug>`
artifact with a supervisor/configuration transport capable of receiving the
admitted configuration and secret slots. Consequently production wiring
constructs the administrator without a runtime adapter, and test/enable/disable
return unavailable instead of pretending an already-running plugin was
configured or supervised. Closing this requires the real artifact and its
documented transport; credentials or process control must not be fabricated in
this repository.
