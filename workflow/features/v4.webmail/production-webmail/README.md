# production-webmail

Full-finish feature split created after cold audit rejected seam-only completion.

## State

Done. Production mailbox-specific IMAP, SMTP, quota, protected
credential/key loading, exact-sender sign-and-verify, durable single-claim
submission, and ambiguous-delivery handling are implemented and reference-stack
smoked. The interactive session-bound three-pane client, stable UID actions,
compose/send, attachments, responsive navigation, keyboard/action parity,
themes, strict CSP, and real Chromium interaction proof are implemented. The
committed tree passed focused normal/race tests, real Chromium, reference
Postfix/Dovecot/Rspamd runtime smoke, containerized UI smoke, one hostile repair
loop, and two independent clean reviews.
