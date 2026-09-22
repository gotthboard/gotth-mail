# GOTTH identity library releases

State: `done`

The owner selected MIT for `gotth-oidc` and `gotth-scim`. GOTTH Mail now pins
their first immutable public releases exactly:

- `github.com/gotthboard/gotth-oidc v0.1.0`
- `github.com/gotthboard/gotth-scim v0.1.0`

Both releases passed their repository gates and clean public-consumer tests.
Their annotated tag objects and peeled commits match exactly between canonical
Forgejo and public GitHub. Live GOTTH Mail evidence proves OIDC login, exact
subject binding, scoped role enforcement, the Authentik SCIM lifecycle,
session revocation, app-password IMAPS compatibility, restart persistence,
backup, and isolated restore.

These are independent pre-1.0 library versions. GOTTH Mail's product version
does not force identity-library version numbers or compatibility promises.
