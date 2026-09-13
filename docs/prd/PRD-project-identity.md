# GOTTH Mail project identity

## Problem

The project was created as `GOTTH Mail`, outside the canonical `gotth-*`
product series. That name now disagrees with the product portfolio, repository
ownership, executable names, Go module path, protocol namespace, configuration
surface, and operator language.

## Required identity

- Product display name: **GOTTH Mail**
- Repository slug: `gotth-mail`
- Canonical Forgejo repository: `gotthboard/gotth-mail`
- Public distribution repository: `gotthboard/gotth-mail` on GitHub
- Go module: `forgejo/gotthboard/gotth-mail`
- Server executable: `gotth-mail`
- Operator CLI: `gotth-mailctl`
- Plugin runner: `gotth-mail-plugin`
- Environment prefix: `GOTTH_MAIL_`
- Protobuf namespace: `gotth.mail.*`

## User-visible behavior

All current product, administrator, CLI, configuration, diagnostics, container,
and protocol surfaces identify the system as GOTTH Mail. Historical commits,
append-only workflow events, changelog entries, and dated evidence remain
historically accurate and are not rewritten.

## Acceptance criteria

1. Forgejo owns the canonical private repository at
   `gotthboard/gotth-mail`; the former API path redirects and obsolete Git
   transport paths fail closed.
2. Current source, tests, configuration, documentation, workflow state, and
   generated protobuf bindings use the required identity.
3. The renamed commands build and the repository test suite passes.
4. Current non-historical files contain no accidental former-name identifiers.
5. Existing tags and commit history remain immutable.
6. The GitHub distribution repository and push mirror are proven at the same
   refs. Until then, the identity feature remains explicitly blocked.

## Non-goals

- Completing unfinished v2-v5 functionality.
- Deploying GOTTH Mail to production.
- Renaming third-party Mailu, Postfix, Dovecot, Rspamd, Roundcube, or Authentik.
- Rewriting historical evidence to pretend it was produced under the new name.
