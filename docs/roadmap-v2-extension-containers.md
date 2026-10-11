# V2 roadmap: one container per extension

Status: planned requirement, recorded 2026-10-01. This is not implementation,
verification, release or deployment evidence.

## Scope

This GOTTH-wide V2 requirement applies to gotth-mail wherever it hosts,
implements or supports extensions. Shared libraries retain their existing
boundaries: this does not turn every library into a daemon or require every
repository to implement an extension host or administrator UI. V2 is a future
product-roadmap milestone, not a renaming of existing internal workstream IDs.

## Required behavior

- Each deployed extension runs in its own container. Separate child processes
  inside a shared host or multi-extension container do not satisfy this V2
  requirement. Concrete extensions retain their separate repository identities.
- Docker Compose files support starting and stopping selected extension
  services as needed, without tearing down the entire application stack.
- Host extension-management pages show available extensions and their runtime
  status, with checkboxes and explicit Load selected / Unload selected controls.
  These controls manage runtime lifecycle, not merely which records are shown.
- Unloading stops the selected extension without uninstalling it or deleting
  its persistent configuration, secrets or data. Deletion remains a separate,
  explicitly authorized operation.
- Existing host authentication, capability grants, health/readiness admission,
  routing revocation before shutdown, confirmation and audit boundaries remain
  authoritative. A running container alone is not permission to route work.

## Design and implementation boundaries

Compose integration and the UI-to-lifecycle control path require a reviewed
architecture and implementation specification before code changes. Container
engine privileges, identity, network/IPC access, secrets, resource limits,
shutdown and failure recovery must be explicit. This requirement grants no
Docker socket, direct product-database or broad host access to extensions or
the shared extension foundation. It does not make existing render/plan/check
commands into deployment commands.

Current releases and APIs are not changed by this roadmap note. Implementation
and deployment remain separate work; no Compose file or runtime is changed here.
