# v1 Mail Core final root admission review

Date/time: 2026-07-16 09:03 CDT

Verdict: **PASS for local root completion.**

## Review basis

A fresh cold admission review rejected v1 after the real runtime smoke passed because remaining v1 scope and workflow blockers were still real:

- root remained `in_progress` in `workflow.toml`;
- mail admin UI/CRUD surfaces were missing;
- `gmf doctor --format text|json` was missing;
- first plugins only exposed generic control/capabilities and not seam-specific service contracts;
- live reference doctor did not prove ACME/manual-cert behavior loudly;
- historical changelog/evidence entries still used current-commit placeholders;
- the worktree was dirty from replacing the brittle SMTP `nc` harness.

Those blockers were addressed before root completion.

## Fixes admitted

- Replaced brittle sleep-driven `nc` SMTP smoke sections with deterministic Python `smtplib` clients while preserving real Postfix policy rejection and alias delivery proof.
- Added `gmf doctor --format text|json` with text and JSON output plus unsupported-format rejection.
- Added a minimal mail admin store and GOTTH/server-rendered UI surfaces for Domain CRUD, User CRUD, Alias CRUD, DNS/DKIM screens, doctor screens, lookup debugger UI, and plugin status/config screens.
- Added seam-specific first-plugin contracts for DNS zone export, certificate request/loud manual ACME failure, backup verification, and Roundcube webmail provider config.
- Wired reference runtime doctor data so `/api/v1/doctor` exposes plugin health and `acme_not_configured_reference_manual_mode` rather than silently pretending ACME succeeded for `example.test`.
- Fixed historical v1 changelog and evidence commit placeholders to real hashes.
- Marked `v1.mail-core` done in `workflow.toml` and appended a workflow event.

## Admission constraints

This admits v1 as the reference mail-core control-plane milestone, not production-grade v2 identity/provisioning or v4 custom webmail. Broader hostile-content webmail security, production ACME issuance against real domains, and deeper plugin external-provider matrices remain later-version scope.

## Verification required

- `go test ./...`
- `git diff --check -- .`
- `scripts/reference-runtime-smoke.sh`

Root is not admissible unless all three pass after this review file is present.
