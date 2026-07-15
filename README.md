# GopherMailForge

GopherMailForge is a Docker/Compose-deployed Go control plane and deployment system for a self-hosted mail stack. It uses Mailu as the reference architecture and executable behavioral specification, while keeping the control plane explicit: typed configuration, audited mutations, daemon-facing contracts, and containerized plugin mechanisms.

This repository is currently in the planning/specification phase. Do not jump straight into implementation; follow the documented sequence.

## Documentation

- [Product requirements](docs/prd/PRD.md)
- [Architecture](docs/architecture/ARCHITECTURE.md)
- [Implementation specifications](docs/implementation/IMPLEMENTATION.md)
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

Root implementation worktrees are created under `/tmp/gophermailforge-worktrees` and recorded in `workflow.toml`.

## License

MIT. See [LICENSE](LICENSE).
