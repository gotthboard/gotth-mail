# v4 durable mailbox-owned draft store evidence

Status: local configured-SQL slice repaired; v4 root remains incomplete and dependency-constrained.

## Scope

Implement durable mailbox-owned webmail draft storage without requiring live IMAP, live SMTP, browser automation, Authentik, Mailu, Telegram, or OpenPGP private keys. This is not v4 admission.

## Implementation

- Added `webmail.DraftStore` as a narrow persistence seam for draft put/get.
- Preserved existing map-backed behavior through the default memory draft store when no durable store is configured.
- Added `webmail.SQLDraftStore` using the existing `webmail_drafts` table.
- Follow-up repair extended `webmail_drafts` to persist reply/forward linkage and attachment metadata/content payloads.
- Added `Sender.SaveDraftContext` and `Sender.DraftContext` so API callers can surface persistence errors instead of silently swallowing them.
- `Sender.Submit` now persists draft state transitions through the configured store: `queued_for_submission`, `submitted`, `failed`, and `sent`.
- Webmail API wiring uses `SQLDraftStore` automatically when `api.Server.AuditDB` is configured and the provided sender has no explicit draft store.
- Authenticated API mailbox ownership checks remain in place before submit; the draft store does not become an authorization mechanism.

## Tests

- `internal/webmail/sql_draft_store_test.go` verifies SQL draft persistence across fresh store wrappers, reply/forward linkage persistence, attachment payload persistence, and submit state persistence through SQL.
- `internal/api/api_test.go` verifies the webmail API writes drafts to SQL when a DB is configured, preserves reply/forward/attachment metadata, and persists `sent` state after submit.
- Existing ownership, non-colliding draft ID, OpenPGP/MIME, and API tests continue to pass.

## Verification

- `go test -count=1 ./internal/webmail ./internal/api ./internal/store` passed.

## Remaining v4 blockers

- Production IMAP adapter and live Dovecot smoke. **Repaired for IMAP transport; see `2026-07-18-containerized-webmail-imap-smoke.md`.**
- Production SMTP submission adapter and live Postfix smoke. **Repaired for SMTP transport; see `2026-07-18-containerized-webmail-smtp-smoke.md`.**
- Real OpenPGP/MIME signing/verification with exact-sender key-state matrix.
- Raw MIME parser and hostile fixture corpus.
- Parser-backed rich HTML sanitizer or explicit text-only product decision with browser proof.
- Attachment/reply/forward draft metadata durability. **Repaired for configured SQL paths; see `2026-07-18-sql-draft-metadata-durability.md`.**
- Custom webmail UI/container reachability.
