# production-webmail

Full-finish feature split created after cold audit rejected seam-only completion.

## State

In progress pending final committed-tree admission. Production mailbox-specific IMAP, SMTP, quota, protected
credential/key loading, exact-sender sign-and-verify, durable single-claim
submission, and ambiguous-delivery handling are implemented and reference-stack
smoked. The interactive session-bound three-pane client, stable UID actions,
compose/send, attachments, responsive navigation, keyboard/action parity,
themes, strict CSP, and real Chromium interaction proof are implemented. This
candidate is not marked done until the final gates and independent clean
reviews pass.
