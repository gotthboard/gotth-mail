# GopherMailForge

GopherMailForge is a Docker/Compose-deployed Go control plane and deployment system for a self-hosted mail stack. It uses Mailu as the reference architecture and executable behavioral specification, while keeping the control plane explicit: typed configuration, audited mutations, daemon-facing contracts, and containerized plugin mechanisms.

This repository is currently in the planning/specification phase. Do not jump straight into implementation; follow the documented sequence.

## Documentation

- [Product requirements](docs/prd/PRD.md)
- [Architecture](docs/architecture/ARCHITECTURE.md)
- [Implementation specifications](docs/implementation/IMPLEMENTATION.md)
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

Root implementation worktrees are created under `/tmp/gophermailforge-worktrees` and recorded in `workflow.toml`. Every meaningful repository change must update [docs/CHANGELOG.md](docs/CHANGELOG.md) in the same commit.

## Current Blockers

- **v2 identity provisioning:** final live Authentik browser/passkey authorization-code redemption and live `gophermailforge-admins` group-claim assertion still require an interactive browser session plus the runtime client secret. Local OIDC redirect, discovery/JWKS loading, SQL identity/session/token/app-password persistence, PBKDF2 verifier validation, and local group-claim preservation are implemented, but the live callback proof is not finished.
- **v3 ops/import/admin:** configured-path implementation repairs are complete for SQL audit/retention, isolated SQL backup restore verification, verified-backup snapshot linkage, canonical SQL bulk mutations, and live Mailu config-export import into canonical SQL. Mailu import compatibility now has a repo-owned containerized Compose smoke fixture under the `mailu-import` profile; it does not depend on an ad hoc host Mailu install and does not expose production mail ports. Root admission remains constrained by the v2 live Authentik dependency; do not claim native Dovecot verification for wrapped Mailu hashes because they require the matching Authentik custom password hasher described in the password-hashing reference.
- **v4 webmail:** durable mailbox-owned draft storage is now implemented for configured SQL paths, including API wiring, persisted submit state, reply/forward linkage, and attachment payload metadata/content. Production SMTP and IMAP transports now have real network adapters plus repo-owned containerized Postfix/Dovecot/Rspamd smoke coverage. A minimal custom `/webmail` shell now has repo-owned container reachability smoke coverage; Roundcube remains only the external provider reference. Raw MIME hostile fixture coverage is present, v4 explicitly uses conservative text-only HTML rendering until a real rich-HTML renderer is designed, and real OpenPGP/MIME signing plus exact-sender verification is implemented with containerized smoke coverage. Remaining deployment work is production key storage/unlock lifecycle, not fake unsigned submission.
- **v5 notifications:** local notification alert core is implemented with bounded sanitized payloads, secret redaction, configured SQL delivery-status persistence/API, explicit SQL actor mapping, read-only command dispatch/audit, runtime summary providers, Telegram update receiver core, SQL approval binding/replay/mismatch/expiry protections, narrow approved queue mutation execution, and a notification-specific gRPC SendAlert/SendPrompt seam in the repo-owned plugin container. Remaining blockers are live Telegram delivery proof and OpenPGP/MIME signed outbound email notifications with no unsigned fallback.

## License

MIT. See [LICENSE](LICENSE).
