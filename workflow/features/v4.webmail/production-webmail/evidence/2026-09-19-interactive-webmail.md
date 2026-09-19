# Interactive production webmail candidate

Date: 2026-09-19 13:21 CDT

State: admitted after committed-tree verification and two independent clean reviews.

## Closed gaps

- `/webmail` is an interactive three-pane GOTTH Mail client rather than a
  reachability shell. It implements folders, dense sortable message rows,
  current-folder search, reading, quota, compose/save/send, saved-draft
  list/reopen/edit, reply/reply-all/forward, attachments and attachment state,
  read/unread with folder counts, flag/unflag, move/delete, pane placement/resizing,
  keyboard commands, context acceleration with visible command parity,
  responsive drill-down, and light/dark themes.
- Browser authority comes from the existing durable OIDC session bound to one
  mailbox. Mutations require the separate CSRF cookie/header proof. Bearer
  tokens and mail credentials are not placed in browser storage.
- IMAP reads and actions use stable UIDs. Deletion uses UID-scoped expunge and
  cannot expunge another message merely because it was already marked deleted.
- Message lists fetch only bounded header/flag metadata; complete body and
  attachment content is fetched only when the user opens a message.
- Saved-draft lists likewise return summaries. Body and attachment bytes use
  the owned detail route, and edits condition on mailbox ownership plus an
  editable state so they cannot revive a concurrently claimed submission.
- Attachment downloads are authenticated, forced to attachment disposition,
  served as `application/octet-stream`, marked `nosniff`, and never cached.
- Hostile HTML remains text data. The document uses a strict same-origin CSP,
  blocks remote message content, and has no unsafe HTML rendering path.
- Missing Sieve support is explicit in the disabled Rules command; the UI does
  not fabricate a rules service.

## Verification

- Focused normal tests cover bound-session same-mailbox authorization,
  cross-mailbox denial, CSRF rejection/acceptance, default signing identity,
  bearer compatibility, message actions, safe attachment download, CSP and
  asset reachability, IMAP UID command shape, flags, and injection rejection.
- `scripts/webmail-browser-smoke.mjs` drives system Chromium through the real
  page and API fixture. It proves authenticated folder/list/read, unread and
  attachment state, safe body rendering, context commands, Reply All,
  compose plus signed submit, saved-draft create/list/reopen/edit/send, pane
  placement, dark theme, and mobile folder-to-list drill-down.
- The rebuilt production-runtime Compose smoke uses real Postfix, Dovecot,
  Rspamd, GnuPG key material, SQL policy, SMTP authentication, Dovecot quota,
  UID flagging, move to Archive, and UID-scoped deletion.

## Boundaries

- Roundcube remains available as the external provider reference.
- Production key custody and live Authentik deployment are operator-owned live
  boundaries and are not faked by repository tests.
- No live credential, mailbox, queue, deployment, DNS record, tag, release, or
  external service changed.
