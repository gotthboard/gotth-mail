# production-webmail

Full-finish feature split created after cold audit rejected seam-only completion.

## State

In progress. Production mailbox-specific IMAP, SMTP, quota, protected
credential/key loading, exact-sender sign-and-verify, durable single-claim
submission, and ambiguous-delivery handling are implemented and reference-stack
smoked. The interactive custom webmail UX and final feature admission remain
open; this checkpoint does not falsely mark the feature done.
