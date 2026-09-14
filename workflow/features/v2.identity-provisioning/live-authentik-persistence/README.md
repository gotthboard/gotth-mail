# live-authentik-persistence

This is the final identity-integration feature inside GOTTH Mail `1.0.0-alpha`.
The historical `v2` prefix is a workstream identifier, not a product version.

The local admission slice binds exact `gotth-oidc` issuer/subject identity to
one active `gotth-scim` User/mailbox projection, creates foreign-keyed durable
sessions atomically with audit, revokes those sessions during SCIM
deprovisioning, and admits same-mailbox app-password self-service with CSRF.

It must fail closed on missing, ambiguous, disabled, email-mismatched, or
reassigned identity state. It must not trust ID-token group claims, mistake
`gotth-authentik` licensing for consumer or live-migration admission, revive a
revoked session, or treat OIDC cookies as mail credentials.

Live provider/browser, installed Authentik SCIM lifecycle, Dovecot client,
restart, backup, and restore proof remain separate evidence gates after the
local mechanism passes.
