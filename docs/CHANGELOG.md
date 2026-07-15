# Changelog

All meaningful repository changes must be recorded here in the same commit that makes the change.

This changelog is operator-facing project history, not a replacement for workflow evidence. Keep entries short, factual, and scoped to what changed.

## Rules

- Update this file for every change that modifies product docs, architecture, implementation specs, workflow state, source code, tests, deployment behavior, security posture, or user-visible behavior.
- Use the newest section at the top.
- Keep pending work under `Unreleased` until a release/version tag exists.
- Include commit hashes for historical entries when useful, but do not make the changelog depend on impossible self-referential commit hashes.
- Do not record private secrets, credentials, raw tokens, or unredacted before/after values.
- Do not use the changelog as a fake done signal; workflow evidence and verification still live under `workflow/`.

## Unreleased

### Added

- Add this changelog and require it to be updated with every meaningful repository change.
- `653b9e7` Add Authentik password hashing compatibility reference docs and require mailbox/app-password verifiers to use Authentik-compatible Django encoded password hashes.

### Changed

- `653b9e7` Tighten PRD, architecture, implementation, import, Dovecot, and workflow verification requirements around password-hash compatibility.
