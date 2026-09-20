# Alpha integration

Tracks completion of every required workstream and reproducible integrated
`1.0.0-alpha.N` artifacts.

State: `blocked`

The integration branch now contains the complete repository implementation and
records both the protected development history and canonical `main` history.
The main-line rename commits were independently applied and then superseded on
the development line, so ancestry was reconciled with a content-preserving
merge rather than replaying stale main content over the verified tree.

Alpha publication remains closed on the exact declared dependencies: public
extension distribution/release parity, live identity adapter acceptance and
immutable OIDC/SCIM tags, deployed Authentik and mail lifecycle evidence, and
the reproducible integrated release artifact and rollback proof.

The production-artifacts child is admitted: five exact images, deterministic
configuration bundle/manifest, real mail-flow smoke, reproducibility, and
Stack replacement/rollback are proved. Alpha integration remains blocked on
the independently distributed webhook artifact, identity-library releases,
live Authentik/mail lifecycle, and recovery evidence. The extension
administrator child is active to close the non-Telegram distribution boundary.
