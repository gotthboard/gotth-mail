# v4 Custom Webmail

ID: `v4.webmail`

State: `in_progress` because the root's declared `v3.ops-import-admin`
dependency remains open; all three v4 implementation children are `done`.

Canonical state lives in `workflow.toml`. This folder holds scoped evidence, review notes, and postmortems only.

The 2026-09-13 classic-interface requirement is implemented by the admitted
production-webmail child: three-pane layout, command bar, responsive drill-down,
themes, keyboard/context action parity, session/CSRF boundaries, durable draft
editing, stable UID actions, and real Chromium plus reference-stack proof.
Earlier seam/model evidence remains historical; the 2026-09-19 evidence is the
expanded interface admission record.

The post-admission canonical-footer change is isolated on
`workflow/feature/v4.webmail.canonical-footer`: it adds only the shared GOTTH
product footer contract, renderer, styling, tests, and deployment evidence.
