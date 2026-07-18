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

The current v2 implementation supports exactly Django `pbkdf2_sha256` verifier strings, matching Authentik's default Django 5.2 password hasher in the checked deployment. It does **not** claim generic Django hasher compatibility. `argon2`, `bcrypt_sha256`, `scrypt`, `pbkdf2_sha1`, and any other Django-recognized algorithms are rejected until GopherMailForge ships local verification support for them and records that expansion explicitly.

Implementation must:

1. Generate new mailbox/app-password verifier strings as Django `pbkdf2_sha256$iterations$salt$digest` values.
2. Accept imported/synchronized password hashes only when they are valid `pbkdf2_sha256` verifier strings.
3. Verify Dovecot passdb secrets against the same stored verifier string used for Authentik-compatible password sync.
4. Reject plaintext password import/export.
5. Reject unknown, non-PBKDF2, deprecated, or policy-disabled hash algorithms unless an explicit migration exception is recorded.
6. Treat broader Django hasher support as future work, not as existing compatibility.

## Non-goals

- Do not store Authentik database rows directly.
- Do not make Authentik the runtime dependency for IMAP/SMTP login.
- Do not treat OIDC sessions as mail-client passwords.
- Do not invent a GopherMailForge-only password hash if an Authentik-compatible Django hash is required.
