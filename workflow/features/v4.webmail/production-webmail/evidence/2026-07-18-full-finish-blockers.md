# v4 full-finish blockers

Status: planned/incomplete after full-finish audit.

Required before v4 can honestly return to done:

- Production IMAP adapter and live Dovecot smoke. **Repaired for IMAP transport on 2026-07-18; see `2026-07-18-containerized-webmail-imap-smoke.md`. Full webmail remains blocked by MIME/security/UI/signing items below.**
- Production SMTP submission adapter and live Postfix smoke. **Repaired for SMTP transport on 2026-07-18; see `2026-07-18-containerized-webmail-smtp-smoke.md`. Full webmail send still depends on OpenPGP/MIME exact-sender signing.**
- Real OpenPGP/MIME signing/verification with exact-sender key-state matrix.
- Raw MIME parser and hostile fixture corpus. **Repaired on 2026-07-18; see `2026-07-18-raw-mime-text-rendering.md`.**
- Parser-backed rich HTML sanitizer or explicit text-only product decision with browser proof. **Resolved by explicit v4 text-only rendering decision on 2026-07-18; rich HTML remains intentionally unimplemented unless the product cutline changes.**
- Persistent mailbox-owned draft store. **Repaired for configured SQL paths on 2026-07-18; see `2026-07-18-durable-draft-store.md`. Reply/forward linkage and attachment metadata/content durability added in the follow-up SQL draft metadata repair.**
- Custom webmail UI/container reachability.

Current repairs closed draft ownership submit authorization, added durable draft schema, wired configured SQL draft persistence/state transitions including reply/forward linkage and attachments, added a real SMTP transport adapter with containerized Postfix delivery smoke coverage, added a real IMAP transport adapter with containerized Dovecot read smoke coverage, and added bounded raw MIME parsing with hostile fixtures plus an explicit text-only HTML rendering decision. They do not claim production webmail is complete.
