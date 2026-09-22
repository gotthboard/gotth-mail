# Alpha integration

Tracks completion of every required workstream and reproducible integrated
`1.0.0-alpha.N` artifacts.

State: `blocked`

The integration branch now contains the complete repository implementation and
records both the protected development history and canonical `main` history.
The main-line rename commits were independently applied and then superseded on
the development line, so ancestry was reconciled with a content-preserving
merge rather than replaying stale main content over the verified tree.

Alpha publication remains closed on the exact unresolved dependencies: public
extension release-asset parity and the reproducible integrated release
artifact/deployment/rollback proof.

The production-artifacts child is admitted: five exact images, deterministic
configuration bundle/manifest, real mail-flow smoke, reproducibility, and
Stack replacement/rollback are proved. The independent identity-library gate
is now closed with `gotth-oidc v0.1.0` and `gotth-scim v0.1.0`. Live Authentik
and Mail evidence covers OIDC login, SCIM provision/disable/restore, scoped
role binding, session revocation, app-password IMAPS compatibility, restart,
backup, and isolated restore. The webhook has an immutable
`v1.0.0-alpha.1` tag with exact Forgejo/GitHub ref parity and a reproducible
archive, but release objects and uploaded asset parity are still unproved. The
extension administrator child remains active until that distribution boundary
is real rather than inferred from mirrored Git refs.
