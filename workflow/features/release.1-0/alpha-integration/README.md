# Alpha integration

Tracks completion of every required workstream and reproducible integrated
`1.0.0-alpha.N` artifacts.

State: `in_progress`

The integration branch now contains the complete repository implementation and
records both the protected development history and canonical `main` history.
The main-line rename commits were independently applied and then superseded on
the development line, so ancestry was reconciled with a content-preserving
merge rather than replaying stale main content over the verified tree.

Alpha publication remains closed on the exact declared dependencies: public
extension distribution/release parity, live identity adapter acceptance and
immutable OIDC/SCIM tags, deployed Authentik and mail lifecycle evidence, and
the reproducible integrated release artifact and rollback proof.
