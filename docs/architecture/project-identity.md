# GOTTH Mail project identity architecture

## Boundary

This change replaces the project's canonical identity without changing the
mail, identity, authorization, storage, or notification mechanisms. It is a
pre-production breaking rename: current first-party callers move together.

## Identifier mapping

| Surface | Canonical value |
| --- | --- |
| Product | `GOTTH Mail` |
| Forgejo owner/repository | `gotthboard/gotth-mail` |
| GitHub distribution repository | `gotthboard/gotth-mail` |
| Go module | `forgejo/gotthboard/gotth-mail` |
| Daemon / CLI / plugin | `gotth-mail`, `gotth-mailctl`, `gotth-mail-plugin` |
| Environment | `GOTTH_MAIL_*` |
| Protobuf package | `gotth.mail.plugin.v1` |
| Protobuf source path | `proto/gotth/mail/plugin/v1` |
| OIDC client and group prefix | `gotth-mail` |
| Cookie prefix | `gotth_mail_` |
| Plugin metadata prefix | `x-gotth-mail-` |
| Database role/database | `gotth_mail` |

## Compatibility and failure model

The system has no admitted production deployment, so carrying a permanent
second set of deprecated names would create ambiguity without protecting real
userspace. Existing development configuration must be regenerated and existing
development OIDC/SCIM objects must be reconciled before the next live identity
proof. Old browser sessions and pending Telegram approval callbacks are invalid
after the rename.

Git history, tags, changelog entries, dated evidence, and append-only workflow
events are immutable historical records. Forgejo's repository redirect is the
only old-name compatibility mechanism. No secret, permission, or runtime trust
boundary changes as part of this rename.

## Integration boundary

GOTTH Mail joins the same project family as the other `gotth-*` repositories:
private canonical development in Forgejo under `gotthboard`, one-way public
distribution on GitHub, and consumer-driven integration with GOTTH Board. The
rename does not make unfinished mail functionality release-ready.
