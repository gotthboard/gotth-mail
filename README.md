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
- **Identity provisioning (`v2` historical ID):** the duplicate OIDC and SCIM protocol implementations have been replaced on the 1.0-alpha development line by exact pinned `gotth-oidc` and `gotth-scim` consumer boundaries. Protected PKCE attempts, application sessions, SCIM resources, indexes, tombstones, mailboxes, verifier projections, and audit records use PostgreSQL. A verified OIDC issuer/subject/email now binds transactionally to exactly one active SCIM User/mailbox; deprovisioning revokes dependent sessions and re-enable cannot revive them. Same-mailbox app-password API and browser self-service derive authority from that durable binding, use a separate CSRF proof, show generated secrets once, retain opaque IDs and labels across restart, cap active PBKDF2 verifiers at eight, and fail closed when mutation or audit cannot commit. The renamed live Authentik issuer at `/application/o/gotth-mail/` still returns 404 while the historical `/gophermailforge/` issuer remains present, so the live provider/profile has not been migrated and no end-to-end login is claimed. SCIM Groups remain deliberately disabled until durable member/role binding is admitted. Legacy email-keyed identities still need an operator-reviewed adoption map, and live Authentik provisioning/deprovisioning plus restart, backup, and restore evidence remain required before this workstream can close.
- **Ops/import/admin (`v3` historical ID):** configured-path implementation repairs are complete for SQL audit/retention, isolated SQL backup restore verification, verified-backup snapshot linkage, canonical SQL bulk mutations, and live Mailu config-export import into canonical SQL. Mailu import compatibility now has a repo-owned containerized Compose smoke fixture under the `mailu-import` profile; it does not depend on an ad hoc host Mailu install and does not expose production mail ports. Root admission remains constrained by the identity workstream's live Authentik dependency; do not claim native Dovecot verification for wrapped Mailu hashes because they require the matching Authentik custom password hasher described in the password-hashing reference.
- **Webmail (`v4` historical ID):** durable mailbox-owned draft storage, production IMAP/SMTP adapters, protected per-mailbox runtime credentials, quota, stable UID reads/actions, reply/forward linkage, safe attachment download, mandatory OpenPGP/MIME signing, exact-sender verification, and ambiguous-delivery state are implemented. `/webmail` is now an interactive session-bound three-pane client with responsive drill-down, compose/send, saved-draft list/reopen/edit, search, sorting, pane placement/resizing, keyboard commands, visible action parity, light/dark themes, and a strict CSP; a real headless Chromium smoke exercises those behaviors. Hostile HTML remains conservative text by design and Roundcube remains usable as the external reference. Live deployment still requires operator-supplied protected credentials/key custody and the separate live Authentik boundary; neither is faked by repository tests.
- **Notifications (`v5` historical ID):** production Telegram and mandatory-OpenPGP signed-email backends are selectable through the control plane, delivery state/evidence is durable, and a persisted transition monitor—not status reads—dispatches doctor/certificate/backup/queue/abuse/deployment/plugin events with deduplication and retry. Telegram commands use authoritative runtime/SQL summaries, an owner-provided private actor-mapping file, authenticated webhook reception, fixed safe denial text, and durable update deduplication. Authenticated queue endpoints create Telegram approvals instead of mutating an in-memory queue. Approvals bind the live Postfix JSON snapshot, execute only documented `postqueue -f` or exact-ID `postqueue -i` operations through the privileged helper, and use an inactive-before-prompt state plus a leased SQL execution state with transactional audit and ambiguous-success recovery. Notification gRPC crosses only loopback or a shared Unix socket; the reference Compose topology uses the Unix socket and a separate signed-email overlay selects exactly one sink. No live credential, webhook registration, queue action, deployment, or signing key was created. The historical root remains open only through its declared `v3` dependency; per-user/role/delegation email identities, public-key discovery, full key lifecycle automation, and production custody remain later release scope rather than alpha claims.

## License

MIT. See [LICENSE](LICENSE).
