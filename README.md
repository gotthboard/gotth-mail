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
- [Workflow manifest](workflow.toml)
- [Coverage posture](workflow/COVERAGE.md)

## Required stack

- Go control plane
- Docker/Compose deployment
- GOTTH admin UI: Go + templ + Tailwind + HTMX
- Postfix, Dovecot, Rspamd, and front/proxy mail stack
- Required adjacent Authentik service/profile
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

- **Identity provisioning (`v2` historical ID):** the admitted `gotth-oidc` and `gotth-scim` modules are compatible and pinned for consumer work, but the in-tree protocol implementations have not yet been replaced by durable GOTTH Mail adapters. Final live Authentik browser/passkey authorization-code redemption, durable role mapping, opaque SCIM-ID adoption, and live provisioning/deprovisioning proof remain required. Local OIDC redirect, discovery/JWKS loading, SQL identity/session/token/app-password persistence, PBKDF2 verifier validation, and local group-claim preservation exist as migration inputs, not stable mechanisms.
- **Ops/import/admin (`v3` historical ID):** configured-path implementation repairs are complete for SQL audit/retention, isolated SQL backup restore verification, verified-backup snapshot linkage, canonical SQL bulk mutations, and live Mailu config-export import into canonical SQL. Mailu import compatibility now has a repo-owned containerized Compose smoke fixture under the `mailu-import` profile; it does not depend on an ad hoc host Mailu install and does not expose production mail ports. Root admission remains constrained by the identity workstream's live Authentik dependency; do not claim native Dovecot verification for wrapped Mailu hashes because they require the matching Authentik custom password hasher described in the password-hashing reference.
- **Webmail (`v4` historical ID):** durable mailbox-owned draft storage is now implemented for configured SQL paths, including API wiring, persisted submit state, reply/forward linkage, and attachment payload metadata/content. Production SMTP and IMAP transports now have real network adapters plus repo-owned containerized Postfix/Dovecot/Rspamd smoke coverage. A minimal custom `/webmail` shell now has repo-owned container reachability smoke coverage; Roundcube remains only the external provider reference. Raw MIME hostile fixture coverage is present, the workstream explicitly uses conservative text-only HTML rendering until a real rich-HTML renderer is designed, and real OpenPGP/MIME signing plus exact-sender verification is implemented with containerized smoke coverage. Remaining deployment work is production key storage/unlock lifecycle, not fake unsigned submission.
- **Notifications (`v5` historical ID):** local notification alert core is implemented with bounded sanitized payloads, fail-closed secret-bearing identifier/detail-key/evidence handling, configured SQL delivery-status persistence/API, explicit SQL actor mapping, read-only command dispatch/audit, runtime summary providers, Telegram update receiver core, SQL approval binding/replay/mismatch/expiry protections, narrow approved queue mutation execution, and a notification-specific gRPC SendAlert/SendPrompt seam whose sink errors are reduced to fixed server-owned status text. The distinct opt-in signed-email system-identity adapter now revalidates its configured sender/key on every delivery, creates seven-bit transport-safe stable-ID MIME, OpenPGP-signs it, verifies the exact raw signed entity and authoritative headers, returns structured exact-sender evidence, and only then submits through a trusted local SMTP relay. The evidence migration validates the complete known ledger, rejects unknown/future versions, and pins migration/isolated restore work to `public`. Real-process gRPC-to-capture-SMTP container tests prove the standalone plugin adapter and post-transport signature; the control-plane alert dispatcher does not yet select or record deliveries through this adapter. No signing key is committed. The feature remains `in_progress`: its operations and app-password dependencies are unresolved, as are core signed-email routing/selection, live Telegram delivery, per-user/role/delegation identity mapping, public-key discovery, full rotation/recovery lifecycle, and production key custody.

## License

MIT. See [LICENSE](LICENSE).
