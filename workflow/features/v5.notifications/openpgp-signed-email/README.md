# v5 Notifications — Mandatory OpenPGP signed email

Feature: `v5.notifications.openpgp-signed-email`

Canonical state lives in `workflow.toml`. This folder holds evidence, review notes, and postmortems only.

Requirement: every outbound email must be OpenPGP-signed. No unsigned fallback is admissible.

Implemented system-notification adapter: the distinct opt-in `signed-email-notification-sink` revalidates one configured sender/private-key binding per delivery, builds seven-bit stable-ID MIME, admits one canonical headerless detached-signature armor block with exactly one SHA-256 packet, verifies the exact raw signed entity and authoritative headers, returns structured exact-sender evidence, and only then submits through a trusted local SMTP relay. Unsupported signing-key capabilities fail permanently before SMTP. It has alert delivery authority only; prompts and mutations are unsupported. The control plane now explicitly selects this adapter over authenticated bounded-deadline gRPC and composes its response with the SQL recorder.

Boundary repairs reject secret-bearing identifiers before bounding, check complete detail keys before truncation, filter typed evidence before memory/SQL/gRPC use, and replace sink-supplied alert or prompt status descriptions/details with fixed server-owned responses. The additive evidence migration validates the complete known ledger, rejects unknown/future versions, preserves the immutable baseline, and pins migration/isolated restore work to `public, pg_catalog` even under a hostile caller search path.

State: `done`

This alpha feature covers the configured system notification identity that the
product currently emits. Per-user/role/delegation selection, public-key
discovery, complete rotation/recovery automation, and production key custody
remain later scope rather than a false claim about deployed secrets.

Current verification evidence: [2026-07-19 signed-email notification runtime](evidence/2026-07-19-signed-email-notification-runtime.md).
