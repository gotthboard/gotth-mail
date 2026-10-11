# GOTTH Mail

GOTTH Mail is a Docker/Compose-deployed Go control plane and deployment system for a self-hosted mail stack. It uses Mailu as the reference architecture and executable behavioral specification, while keeping the control plane explicit: typed configuration, audited mutations, daemon-facing contracts, and containerized plugin mechanisms.

This repository is in staged implementation governed by `workflow.toml`. Do not skip the documented PRD, architecture, implementation-specification, decomposition, verification, and evidence sequence.

## Documentation

- [Product requirements](docs/prd/PRD.md)
- [Architecture](docs/architecture/ARCHITECTURE.md)
- [Implementation specifications](docs/implementation/IMPLEMENTATION.md)
- [Project identity contract](docs/prd/PRD-project-identity.md)
- [1.0 release contract](docs/prd/PRD-release-1.0.md)
- [Changelog](docs/CHANGELOG.md)
- [Authentik password hashing compatibility](docs/reference/authentik-password-hashing.md)
- [GOTTH component adoption contract](docs/reference/gotth-stack-adoption.md)
- [Classic interface language](docs/reference/classic-interface-language.md)
- [Workflow manifest](workflow.toml)
- [Coverage posture](workflow/COVERAGE.md)

## Required stack

- Go control plane
- Docker/Compose deployment
- GOTTH admin UI: Go + templ + Tailwind + HTMX
- Postfix, Dovecot, Rspamd, and front/proxy mail stack
- Required adjacent Authentik service/profile
- `gotth-oidc` for OIDC protocol mechanics and `gotth-scim` for the SCIM
  protocol/storage contract; GOTTH Mail retains product storage, sessions,
  authorization, mailbox projection, audit, and operations policy
- pinned `gotth-extensions` validation, grant, negotiation, lifecycle,
  handshake, and health contracts; Mail retains seam protocols, credentials,
  routing, supervision, policy, mutation, audit, and rollback authority
- Containerized gRPC/protobuf plugins at narrow mechanism seams

## Development workflow

`workflow.toml` is the canonical development-state manifest. Workflow records live under `workflow/`; product documentation lives under `docs/`.

The intended sequence is:

1. PRD
2. Architecture
3. Implementation spec
4. Feature decomposition/worktrees
5. Implementation
6. Tests/verification
7. Evidence/handoff

Canonical root implementation worktree locations must be under the durable `/tank/development/linus/gotth-mail-worktrees` path recorded in `workflow.toml`. Volatile `/tmp` paths may be compatibility symlinks only; they are not canonical storage. Every meaningful repository change must update [docs/CHANGELOG.md](docs/CHANGELOG.md) in the same commit.

## Current Blockers

The historical `v0` through `v5` labels below identify capability workstreams,
not product releases. All required work belongs to the `1.0.0` line: alpha
while incomplete, beta only after feature completion, and stable only after
the complete stack is admitted.

- **Same-domain-only outbound policy (owner priority):** a per-domain option
  restricts every mailbox and system sender in that domain to the
  exact same recipient domain while leaving inbound mailbox delivery
  independent; outbound forwarding is still restricted. It covers SMTP,
  webmail/API, expansions, automated mail, queued retry/replay, and final
  transport; uncertainty defers rather than permits delivery. Repository
  implementation and admission are complete; live activation remains a
  separate operator-controlled deployment action.
- **Extensions:** the shared `gotth-extensions` compatibility kernel is pinned
  to reviewed commit `3822dd7` and now binds each built-in mechanism to an
  exact manifest, host grant, negotiated interface/capability/secret-slot
  session, validated lifecycle, and authenticated challenge/health exchange.
  Existing Mail seam RPCs remain unchanged. The host-owned Extensions setup,
  update, rollback, encrypted-secret, and administrator UI feature is still a
  separate open workstream; no generic invocation API or extension-supplied UI
  was introduced.
- **Identity provisioning (`v2` historical ID):** the duplicate OIDC and SCIM protocol implementations have been replaced on the 1.0-alpha development line by exact pinned `gotth-oidc` and `gotth-scim` consumer boundaries. Protected PKCE attempts, application sessions, SCIM resources, indexes, tombstones, mailboxes, verifier projections, and audit records use PostgreSQL. A verified OIDC issuer/subject/email now binds transactionally to exactly one active SCIM User/mailbox; deprovisioning revokes dependent sessions and re-enable cannot revive them. Same-mailbox app-password API and browser self-service derive authority from that durable binding, use a separate CSRF proof, show generated secrets once, retain opaque IDs and labels across restart, cap active PBKDF2 verifiers at eight, and fail closed when mutation or audit cannot commit. The renamed live Authentik issuer at `/application/o/gotth-mail/` still returns 404 while the historical `/gophermailforge/` issuer remains present, so the live provider/profile has not been migrated and no end-to-end login is claimed. SCIM Groups remain deliberately disabled until durable member/role binding is admitted. Legacy email-keyed identities still need an operator-reviewed adoption map, and live Authentik provisioning/deprovisioning plus restart, backup, and restore evidence remain required before this workstream can close.
- **Ops/import/admin (`v3` historical ID):** configured-path implementation repairs are complete for SQL audit/retention, isolated SQL backup restore verification, verified-backup snapshot linkage, canonical SQL bulk mutations, and live Mailu config-export import into canonical SQL. Mailu import compatibility now has a repo-owned containerized Compose smoke fixture under the `mailu-import` profile; it does not depend on an ad hoc host Mailu install and does not expose production mail ports. Root admission remains constrained by the identity workstream's live Authentik dependency; do not claim native Dovecot verification for wrapped Mailu hashes because they require the matching Authentik custom password hasher described in the password-hashing reference.
- **Webmail (`v4` historical ID):** durable mailbox-owned draft storage, production IMAP/SMTP adapters, protected per-mailbox runtime credentials, quota, stable UID reads/actions, reply/forward linkage, safe attachment download, mandatory OpenPGP/MIME signing, exact-sender verification, and ambiguous-delivery state are implemented. `/webmail` is now an interactive session-bound three-pane client with responsive drill-down, compose/send, saved-draft list/reopen/edit, search, sorting, pane placement/resizing, keyboard commands, visible action parity, light/dark themes, and a strict CSP; a real headless Chromium smoke exercises those behaviors. Hostile HTML remains conservative text by design and Roundcube remains usable as the external reference. Live deployment still requires operator-supplied protected credentials/key custody and the separate live Authentik boundary; neither is faked by repository tests.
- **Notifications (`v5` historical ID):** production Telegram and mandatory-OpenPGP signed-email backends are selectable through the control plane, delivery state/evidence is durable, and a persisted transition monitor—not status reads—dispatches doctor/certificate/backup/queue/abuse/deployment/plugin events with deduplication and retry. Telegram commands use authoritative runtime/SQL summaries, an owner-provided private actor-mapping file, authenticated webhook reception, fixed safe denial text, and durable update deduplication. Authenticated queue endpoints create Telegram approvals instead of mutating an in-memory queue. Approvals bind the live Postfix JSON snapshot, execute only documented `postqueue -f` or exact-ID `postqueue -i` operations through the privileged helper, and use an inactive-before-prompt state plus a leased SQL execution state with transactional audit and ambiguous-success recovery. Notification gRPC crosses only loopback or a shared Unix socket; the reference Compose topology uses the Unix socket and a separate signed-email overlay selects exactly one sink. No live credential, webhook registration, queue action, deployment, or signing key was created. The historical root remains open only through its declared `v3` dependency; per-user/role/delegation email identities, public-key discovery, full key lifecycle automation, and production custody remain later release scope rather than alpha claims.


## Migration-authority deployment protocol

These protocols require dedicated product principals and a dedicated product database cluster. Besides templates, only the current product database and a clean maintenance database named `postgres` are allowed. Retain a verified backup and the old image/config reference, stop every service, and give one trusted superuser an exclusive administration window from the first preflight through the final `COMMIT`. During that window no other actor may create, alter, rename, or drop roles/databases; change memberships, settings, ACLs, or owners; open product sessions; prepare transactions; or run object DDL.

READ COMMITTED catalog reads and advisory locks do not serialize an uncooperative superuser. “One transaction” means rollback atomicity only, not concurrent-superuser exclusion.

Fresh databases use this exact sequence:

1. The distinct installer creates seven passwordless `NOLOGIN` principals and the database/OID-bound phase marker:
   ```sh
   psql --set=ON_ERROR_STOP=1 --dbname "$GOTTH_MAIL_INSTALLER_DATABASE_URL" --file scripts/bootstrap-migration-authority-fresh.sql
   ```
2. Outside repository SQL, provision both app and migrator with SCRAM verifiers using `password_encryption=scram-sha-256`. Do not record plaintext or verifier bytes in SQL files, logs, receipts, or the phase marker.
3. Run the same script a second time. It requires the exact marker, transitional role model, and both SCRAM verifiers; activates only the migrator and advances the marker to prefix-ready. The app remains `NOLOGIN`:
   ```sh
   psql --set=ON_ERROR_STOP=1 --dbname "$GOTTH_MAIL_INSTALLER_DATABASE_URL" --file scripts/bootstrap-migration-authority-fresh.sql
   ```
4. With only `GOTTH_MAIL_MIGRATION_DATABASE_URL[_FILE]`, run `gotth-mail migrate --through 0020_final_queue_artifact_binding`.
5. The installer executes the atomic cutover. It rechecks marker, verifiers, roles, ledger, owners, inventory, and ACL provenance; transfers database/object authority, enables the app, and consumes the marker:
   ```sh
   psql --set=ON_ERROR_STOP=1 --dbname "$GOTTH_MAIL_INSTALLER_DATABASE_URL" --file scripts/bootstrap-migration-authority-fresh-0020.sql
   ```
6. Start normally with distinct app and migrator secrets. Startup applies 0021, closes the migration pool, opens the app pool, validates the current ledger, then wires database-backed services.

Existing exact <=0020 legacy deployments use the upgrade script only after the same backup, dedicated-cluster, stopped-service, and exclusive-window checks:

```sh
psql --set=ON_ERROR_STOP=1 --dbname "$GOTTH_MAIL_INSTALLER_DATABASE_URL" --file scripts/bootstrap-migration-authority-upgrade-0020.sql
```

The first legacy transition requires the current database and every sealed public object to be owned solely by the exact legacy login, exact legacy ACL state, no remote database/dependency/session/prepared-transaction use, and a NULL or SCRAM verifier. MD5 and every other verifier format refuse. After the script commits but before startup, provision the new `gotth_mail_migrator` SCRAM verifier outside repository SQL; if the preserved legacy app verifier was NULL, provision `gotth_mail_app` too. Keep verifier/plaintext bytes out of commands, logs, and receipts, then install the distinct app and migration secret references used by normal startup. An already-app invocation succeeds only as a no-op from the exact completed <=0020 owner/ACL/dependency structure; partial or older cutovers refuse and require restore or separately reviewed remediation.

Plain `psql -f` without `ON_ERROR_STOP` is unsupported. After 0021 commits, rollback means restoring the pre-upgrade database and old secrets/image together; never start the <=0020 binary against a committed 0021 database.

## License

MIT. See [LICENSE](LICENSE).

## V2 extension deployment roadmap

V2 requires one container per extension, independently started and stopped
through Docker Compose, with checkbox-based load/unload controls in host
administration pages. See the [V2 extension-container requirement](docs/roadmap-v2-extension-containers.md).
This is a future requirement, not a claim of current implementation.
