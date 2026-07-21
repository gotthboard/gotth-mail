# Workflow

`workflow.toml` is the canonical development-state manifest.

Folders under `workflow/features/` hold evidence, review notes, and postmortems. They do not redefine state, active feature, dependencies, or done status.

Canonical worktree locations must be under the durable path recorded by `repository.worktree_root` in `workflow.toml`. `/tmp` may contain compatibility symlinks, but must not hold the only copy of uncommitted work.

## Changelog discipline

Every meaningful repository change must update [`docs/CHANGELOG.md`](../docs/CHANGELOG.md) in the same commit. Each entry must include date/time with timezone, commit identifier, affected files, verbose explanation, and verification performed. Workflow evidence stays under `workflow/`; the changelog is the compact human-readable index of changes.
