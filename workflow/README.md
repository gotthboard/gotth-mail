# Workflow

`workflow.toml` is the canonical development-state manifest.

Folders under `workflow/features/` hold evidence, review notes, and postmortems. They do not redefine state, active feature, dependencies, or done status.

Worktrees are created under `/tmp/gotth-mail-worktrees` and recorded in `workflow.toml`.

## Changelog discipline

Every meaningful repository change must update [`docs/CHANGELOG.md`](../docs/CHANGELOG.md) in the same commit. Each entry must include date/time with timezone, commit identifier, affected files, verbose explanation, and verification performed. Workflow evidence stays under `workflow/`; the changelog is the compact human-readable index of changes.
