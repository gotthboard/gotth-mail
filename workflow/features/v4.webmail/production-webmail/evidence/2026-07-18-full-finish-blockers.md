# v4 full-finish blockers

Status: planned/incomplete after full-finish audit.

Required before v4 can honestly return to done:

- Production IMAP adapter and live Dovecot smoke.
- Production SMTP submission adapter and live Postfix smoke.
- Real OpenPGP/MIME signing/verification with exact-sender key-state matrix.
- Raw MIME parser and hostile fixture corpus.
- Parser-backed rich HTML sanitizer or explicit text-only product decision with browser proof.
- Persistent mailbox-owned draft store and custom webmail UI/container reachability.

Current repair closed draft ownership submit authorization and added durable draft schema, but does not claim production webmail is complete.
