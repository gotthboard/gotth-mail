# App-password and Dovecot repair evidence

Feature: `v2.identity-provisioning.app-passwords-ui`

Date: 2026-09-13 CDT

Reviewed head: `cd172cb4dc2a9a6ff3491073faeba06a7f8f6b16`

Target: unfinished GOTTH Mail 1.0-alpha development line
`workflow/feature/release.1-0.identity-library-releases`; product `main` is
outside this admission.

## Contract and GOTTH allocation

The PRD, architecture, implementation specification, feature manifest, README,
and GOTTH adoption record now agree:

- exact pinned `gotth-oidc` remains the browser identity protocol component;
- exact pinned `gotth-scim` remains the mailbox provisioning protocol/storage
  contract;
- GOTTH Mail owns app-password generation, verifier storage, Dovecot passdb
  policy, mailbox/role binding, and audit admission because no reviewed
  `gotth-*` component supplies those mechanisms;
- `gotth-jobs` is excluded from synchronous credential mutation;
- browser self-service is disabled until a verified OIDC session is bound
  through durable identity and role state. The scoped API remains canonical.

No placeholder or unlicensed component was imported to inflate the GOTTH
dependency count.

## Implementation evidence

- Migration `0005_app_password_contract` adds `tokens.public_id`, backfills
  legacy app-password IDs from the formerly overloaded label field, preserves
  verifiers/revocation, and installs ID/label constraints plus a partial unique
  index.
- New records persist a distinct opaque public ID and human label. Both survive
  fresh service construction; plaintext secrets never enter SQL or list
  responses.
- Create locks the mailbox row, counts active credentials, and admits at most
  eight. The token and normalized redacted success audit commit together.
- Revoke locks the token row and commits revocation plus success audit together.
  Injected audit rejection rolls back both create and revoke.
- Configured database startup gives identity/passdb the durable SQL audit
  writer. Otherwise-valid passdb authentication defers if success audit cannot
  be recorded.
- Startup rejects persisted mailboxes with more than eight active app-password
  verifiers. Passdb separately rejects an over-limit runtime projection before
  any app-password PBKDF2 scan.
- Live identity projection installs a daemon state lock. Passdb snapshots only
  the requested mailbox and its bounded verifier slice; create/revoke writers
  cannot race the read or trigger a concurrent-map panic.
- The runtime UI shares the configured identity service but renders no mailbox,
  app-password, secret, or label state. The fake in-process SCIM mutation and
  bearer-header-dependent HTML app-password forms are gone.

The legacy implementation never stored the operator's human label; migration
therefore cannot reconstruct it. It preserves the public ID as the label for
those old rows without guessing. Operators may relabel later when an admitted
surface exists.

## Verification on `development`

The isolated worktree was
`/tank/development/linus/gotth-mail-worktrees/v2.identity-provisioning.app-passwords-ui`.

- focused PostgreSQL store/identity/API/command, daemon, UI, and audit tests:
  pass;
- concurrent creators: exactly eight success and the remainder return the
  explicit limit error; pass;
- create/revoke audit-failure rollback injection: pass;
- stable ID/label/revocation/restart and durable passdb-use audit: pass;
- concurrent passdb readers with create/revoke projection under the race
  detector: pass;
- `go test ./...`: pass;
- `go test -race ./...`: pass;
- `go vet ./...`: pass;
- all three command builds: pass;
- `go mod verify`: pass;
- `git diff --check`: pass;
- tested worktree clean at the reviewed head.

Cross-package focused coverage was 72.0%. Relevant function coverage included:

- `CreateAppPassword`: 88.7%
- `RevokeAppPassword`: 91.7%
- `activeAppPasswordCountLocked`: 100.0%
- `VerifyDovecot`: 92.9%
- `DovecotPassdb`: 84.6%
- `auditPassdb`: 100.0%
- `mailboxAuth`: 94.4%
- `appPasswordSuccessEvent`: 100.0%
- `WriteSQL`: 84.6%
- `runtimeMux`: 93.3%
- migration registration/application helpers: 100.0%

The uncovered branches are chiefly injected driver/transaction failure sites,
unavailable-entropy ID generation, and unrelated legacy routes in broad
packages. Faking database driver layers solely to make the number read 100%
would add more mechanism than it verifies. The consequential validation,
authorization, missing-state, limit, rollback, restart, audit, normalization,
and concurrency paths are covered.

## Graph and review

Graphify `0.9.32` extracted the reviewed code-only tree to
`/home/linus/.cache/openclaw-graphify/gotth-mail-app-passwords-ui/graphify-out/graph.json`:

- 1,747 nodes
- 4,260 edges
- 78 communities
- SHA-256
  `9fe8c91ad282a2ee6969c9acf8c7376927e0cfb3dadc988a4300c3ab632482d2`

Graphify skipped three potentially sensitive fixture files and five SQL files
because its optional SQL parser is absent; no dependency was installed. A tool
bug emitted an extra repo-local `graphify-out`; it was moved to
`/tmp/gotth-mail-app-passwords-ui-graphify-out-cd172cb`, leaving the worktree
clean.

Cold review found and forced two material repairs:

1. serializable transactions leaked PostgreSQL `40001` aborts under concurrent
   creators despite an exact mailbox row lock; read committed plus that lock is
   the smaller correct mechanism;
2. daemon map projection raced passdb and cloned the whole identity map per
   authentication; the bounded mailbox snapshot and shared projection lock
   remove both defects.

Final verdict: **Accept with constraints**. The durable API/passdb repair is
admissible on the unfinished development line. Browser self-service, real
Authentik subject/mailbox/role binding, real client login against deployed
Dovecot, backup/restore proof, component tags, product `main`, and deployment
remain outside this admission. The feature root therefore remains
`in_progress` until the dependent live integration closes those gates.
