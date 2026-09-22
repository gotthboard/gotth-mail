# Live Authentik and Mail identity/recovery evidence — 2026-09-21

## Scope

The owner authorized the live `v1.0.0-alpha.1` SCIM lifecycle on
`mail.alhstudios.com`. The proof used one dedicated test identity and did not
expose credentials or widen the public API surface.

## Identity lifecycle

- Authentik provisioned `gotth-mail-scim-alpha` with opaque subject/externalId
  `87b7acec-3dd9-4c71-a1e4-d1aaedc8cc16`.
- GOTTH Mail projected mailbox `scim-alpha@alhstudios.com` with mailbox ID
  `5a09151f-71c9-4b86-84c1-9b7e90651cd4` and preserved the existing domain's
  authoritative ID.
- Real browser authorization-code login with PKCE succeeded.
- The preview/confirm operator path granted `domain_manager` only for
  `alhstudios.com`; `/admin/dns` admitted that exact identity and scope.
- Authentik disable atomically disabled the mailbox and revoked the active Mail
  session. The old browser session failed with `identity session is invalid`.
- Restore re-enabled the mailbox without reviving the revoked session. A fresh
  login succeeded and retained the scoped role.

## Mail-client and restart proof

- The exact self-service app-password route created one secret shown once;
  only its verifier remained in PostgreSQL.
- External IMAPS authentication succeeded with the app password.
- After restarting Authentik and all six Mail services, the browser identity,
  scoped administrator route, and IMAPS app password still worked.
- Unlisted mailbox APIs remained public `404`; the only new public route was
  the exact authenticated `/identity/app-passwords` page.

## Backup and isolated restore

- Protected before/after Authentik and Mail PostgreSQL custom-format dumps were
  created with inventories and SHA-256 sums.
- `pg_restore --list` validated both dumps.
- Each dump restored into a separate temporary PostgreSQL 16 instance on
  tmpfs; no live database was overwritten.
- The Authentik restore contained the active user, SCIM provider/link, and
  managed group.
- The Mail restore contained the enabled mailbox, exact subject, scoped role,
  one revoked old session, and one active app-password verifier.

All temporary restore containers were removed after verification. Secrets,
bearer tokens, client credentials, and password values are deliberately absent
from this evidence.
