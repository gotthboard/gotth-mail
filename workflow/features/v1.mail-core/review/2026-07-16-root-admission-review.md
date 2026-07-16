# v1 Mail Core root admission review

Date/time: 2026-07-16 02:02 CDT

Verdict: **Reject for root admission.**

## Exact flaw

The branch implements useful v1 control-plane primitives, but it does not yet prove a real mail-server deployment. The v1 PRD requires Postfix, Dovecot, and Rspamd to run against GopherMailForge contracts and a smoke test proving SMTP submission, receive path, alias delivery, IMAP login, DKIM signing, and webmail visibility.

That has not happened.

## Why this blocks

Unit tests for HTTP/JSON contract models are not a substitute for daemon runtime integration. Generated files that name Postfix/Dovecot/Rspamd endpoints are not proof that those daemons can consume the config or that mail flows.

Admitting this root as v1 would be fake success.

## Evidence checked

Passed gates on the current branch:

```text
go test ./...
git diff --check -- .
sudo docker build -t gophermailforge:v1-smoke .
```

Branch commits reviewed:

```text
824faf1 Implement v1 daemon contracts
d77df0e Generate v1 daemon config
6b8fa66 Add v1 DNS TLS ACME diagnostics
6456a60 Add v1 first plugin containers
f7f8162 Add v1 diagnostics smoke snapshot surfaces
```

## Missing root acceptance evidence

Still missing:

- actual Postfix service in reference Compose
- actual Dovecot service in reference Compose
- actual Rspamd service in reference Compose
- daemon-native adapter/config integration proving those daemons use the internal HTTP/JSON contracts
- SMTP submission smoke
- receive path smoke
- alias delivery smoke
- IMAP login smoke
- DKIM signing smoke
- selected webmail visibility smoke

## Smaller acceptable next fix

Add a narrow child feature, e.g. `v1.mail-core.reference-runtime-smoke`, that wires real Postfix/Dovecot/Rspamd containers into reference Compose, points them at generated config/adapters, and proves the mail-flow smoke. Only after that passes should v1 root move from `in_progress` to `done` or get an admission PR.

## Boundary notes

- No v1 admission PR should be opened as complete from this branch yet.
- Do not start v2 until this root blocker is resolved or explicitly split with an approved exception.
- This is not userspace breakage yet because the branch has not merged. It would become userspace damage if merged as “v1 Mail Core.”


## Follow-up blocker fix evidence

`v1.mail-core.reference-runtime-smoke` was added after this rejection to address the missing runtime proof. The new evidence lives at:

- `workflow/features/v1.mail-core/reference-runtime-smoke/evidence/2026-07-16-reference-runtime-smoke.md`

Do not rewrite this rejected verdict as if it had passed originally. Run a fresh root admission review against the later commit before opening the v1 admission PR.
