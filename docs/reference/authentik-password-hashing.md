# Authentik Password Hashing Compatibility

## Source check

Source checked against `goauthentik/authentik` main branch on 2026-07-15.

Relevant source facts:

- Authentik uses Django 5.2.x.
- Django stores password hashes as `algorithm$iterations$salt$hash`.
- Django 5.2 defaults to PBKDF2-SHA256 for new password storage unless `PASSWORD_HASHERS` is overridden.
- Django verifies by selecting the hasher named by the algorithm embedded in the stored hash string.
- Authentik does not define a project-local `PASSWORD_HASHERS` override in `authentik/root/settings.py`.
- `authentik/core/models.py` validates imported password hashes with Django `identify_hasher(password_hash)`.
- `authentik/core/management/commands/hash_password.py` hashes passwords with Django `make_password(password)`.
- Authentik's user API supports setting a pre-hashed Django password value and rejects invalid hash formats.

## GopherMailForge requirement

GopherMailForge mailbox-password and mail-client verifier storage must be compatible with Authentik's Django encoded password-hash format, not a private mail-only hash scheme.

The stored verifier string must carry the algorithm identifier and parameters in the Django encoded form, for example `pbkdf2_sha256$...` for the current default or another Django-recognized algorithm selected by the configured Authentik deployment.

Implementation must not assume a hard-coded algorithm forever. It must:

1. Record the configured Authentik-compatible hasher profile.
2. Generate new mailbox/app-password verifier strings using that profile.
3. Accept only Django-recognized encoded hashes when importing or synchronizing password hashes.
4. Verify Dovecot passdb secrets against the same stored verifier string used for Authentik-compatible password sync.
5. Reject plaintext password import/export.
6. Reject unknown, deprecated, or policy-disabled hash algorithms unless an explicit migration exception is recorded.

## Non-goals

- Do not store Authentik database rows directly.
- Do not make Authentik the runtime dependency for IMAP/SMTP login.
- Do not treat OIDC sessions as mail-client passwords.
- Do not invent a GopherMailForge-only password hash if an Authentik-compatible Django hash is required.
