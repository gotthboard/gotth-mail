# GOTTH Mail live Authentik profile — 2026-09-13

Status: additive OIDC/enrollment profile live; browser callback and SCIM
lifecycle still blocked.

Product line: `1.0.0-alpha`.

Historical workflow ID: `v2.identity-provisioning.live-authentik-persistence`.
The `v2` prefix is not a product version.

## Authority and boundary

Danny selected MIT for all owner-authored GOTTH repositories and then directed
the explicitly described live Authentik issuer migration to continue. The
migration used `gotth-authentik` revision
`77c811c18fe3c107f6f3e97ce3f9a3850a685300` only as a build-time,
secret-free desired-state renderer.

GOTTH Mail retains live apply and rollback, generated-secret handling,
application membership, SCIM provider, runtime configuration, and every
product authorization decision. `gotth-mail-users` is an application access
gate only. Adding `Dan`, the sole member of the historical
`gophermailforge-admins` group, to that gate created no GOTTH Mail role,
mailbox, SCIM resource, or trusted token claim.

## Canonical profile

- application slug: `gotth-mail`
- provider name: `gotth-mail-oidc`
- client ID: `gotth-mail`
- access group: `gotth-mail-users`
- issuer: `https://auth.dannyhunn.com/application/o/gotth-mail/`
- strict pre-production callback:
  `http://127.0.0.1:18080/api/v1/oidc/callback`
- manifest SHA-256:
  `a59e50d6f7c54418ccf68db5e6e5795c1f416c53c43521fa9fefac5529ddfc7b`
- blueprint SHA-256:
  `5bcbe9141f7a59eb7416faa0de0ced9ae4f95ffdfb4b15408cf576eed369a9ad`

The manifest and blueprint contain no client secret, bearer token, password
value, cookie, or private key. Authentik generated the confidential client
secret. It was captured without terminal disclosure in the root-only rollback
directory for a later deployed runtime; it is not in Git or this evidence.

## Rollback and live application

Before mutation, the operator created root-owned mode-0700 directory
`/root/gotth-mail-authentik-migration-20260914T004606Z` on the development/live
host. It contains mode-0600 Authentik Compose inputs, a custom-format
PostgreSQL dump, checksum record, and the generated client secret. The dump
checksum passed and `pg_restore --list` read the archive successfully.

The exact blueprint first validated and applied inside a rollback-only Django
transaction. The transaction proved the new application could be created and
left zero `gotth-mail` objects after rollback while the historical application
remained.

The real import then created the new objects beside the historical provider.
A second import was idempotent and retained the exact generated client secret.
The historical `gophermailforge` application/provider was not renamed,
deleted, disabled, or rebound.

## Live verification

- new discovery: HTTP 200 with exact `gotth-mail` issuer
- historical discovery: HTTP 200 with exact `gophermailforge` issuer
- new JWKS: non-empty RSA key with `kid`
- new authorization endpoint: redirect/state preservation smoke passed with
  client ID `gotth-mail` and the strict callback
- enrollment flow: HTTP 200
- end-session endpoint: HTTP 302
- Authentik server, worker, and PostgreSQL containers: healthy
- access group: one explicitly reviewed active member (`Dan`)
- Authentik SCIM provider count: zero

## Honest remaining gates

This is not a completed authorization-code login. No GOTTH Mail runtime is
listening on `127.0.0.1:18080`; the host's separate LAN-bound port 18080 service
is unrelated. A public deployment therefore still needs an exact HTTPS public
URL/callback, the generated secret supplied from a root-readable file, and an
interactive login/passkey callback with issuer/subject/email-to-SCIM binding.

This is also not SCIM evidence. The installed Authentik has no SCIM provider,
and GOTTH Mail has no deployed live SCIM endpoint or credential. Provision,
login, disable, session revocation, deprovision, restart, backup, isolated
restore, and rollback remain mandatory before the historical provider may be
retired or the workstream may be marked done.

No GOTTH Mail product deployment, product-main merge, tag, or release occurred.
