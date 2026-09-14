# GOTTH Mail classic interface contract evidence

Feature: `v4.webmail.search-security-ux`

Timestamp: 2026-09-13 19:06 CDT

## Owner requirement

Danny requires custom GOTTH Mail webmail to provide an Outlook
Classic-inspired but distinctly GOTTH Mail experience. The accepted direction
is a dense desktop-first three-pane workflow with a traditional command bar,
configurable reading pane, keyboard navigation, context-menu acceleration,
sortable columns, restrained blue/gray light and dark themes, and a responsive
mobile drill-down. The admin GUI shares applicable visual patterns but remains
a separate authority.

## Documentation trace

- `docs/reference/classic-interface-language.md` defines the shared product
  language, responsive behavior, intellectual-property boundary, security,
  and accessibility invariants.
- `docs/prd/PRD-v4-webmail.md` records scope and acceptance criteria.
- `docs/architecture/v4-webmail.md` records presentation and state ownership.
- `docs/implementation/v4-webmail.md` records the concrete layout,
  interaction, responsive, theme, asset, and browser-test contracts.
- v0 PRD, architecture, and implementation docs bind the separate admin shell
  to applicable shared tokens and patterns without transferring authority.
- `workflow.toml` carries the expanded verification gates.

## Admission boundary

This change admits the requirement and documentation only. It does not claim
that the current minimal `/webmail` shell implements the classic interface.
The v4 workstream remains `in_progress` until the required browser,
accessibility, responsive, theme, asset-provenance, and no-bypass evidence
passes against the implementation.

## Verification

- documentation links resolved within the repository
- previous v4 completion record explicitly retained as historical narrower
  evidence rather than silently rewritten
- `go test ./internal/webmail`: pass
- `git diff --check`: pass
