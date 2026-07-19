# v4 SQL draft metadata durability evidence

Status: configured SQL draft path repaired for attachment/reply/forward metadata durability.

## Scope

Close the remaining durable draft metadata gap without pretending this completes webmail security/UI/signing work.

## Implementation

- Extended `webmail_drafts` schema with:
  - `reply_to`
  - `forward_of`
  - `attachments_json`
- Updated `webmail.SQLDraftStore` to persist and reload:
  - reply source message ID
  - forward source message ID
  - attachment filename/content type/size/content payload
- Kept mailbox ownership guard unchanged: `ON CONFLICT` updates still require the existing draft mailbox to match the incoming mailbox.
- API draft creation keeps ignoring caller-supplied draft IDs while preserving authenticated-mailbox metadata fields.

## Verification

- `go test -count=1 ./internal/webmail ./internal/api ./internal/store` passed.
- Added SQL store regression coverage proving reply/forward linkage and attachment content survive reload.
- Extended API configured-path coverage proving HTTP draft creation persists reply/forward linkage and attachment payload data through `SQLDraftStore`.

## Remaining blockers

- Real OpenPGP/MIME signing/verification with exact-sender key-state matrix.
- Raw MIME parser and hostile fixture corpus.
- Parser-backed rich HTML sanitizer or explicit text-only product decision with browser proof.
- Custom webmail UI/container reachability.
