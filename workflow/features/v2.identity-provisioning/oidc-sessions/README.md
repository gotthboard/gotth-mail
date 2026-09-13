# Adopt gotth-oidc with protected attempts and durable sessions

ID: `v2.identity-provisioning.oidc-sessions`

State: `in_progress`

Current contract: replace the duplicate in-tree OIDC protocol implementation
with the exact pinned `gotth-oidc` API while preserving GOTTH Mail's route and
cookie userspace. Persist only protected attempt material, consume it exactly
once, and prove restart and concurrent-replay behavior.

Canonical state lives in `workflow.toml`. This folder holds scoped evidence, review notes, and postmortems only.
