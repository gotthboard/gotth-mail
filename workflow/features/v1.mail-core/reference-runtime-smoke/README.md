# v1 reference runtime and smoke

Feature: `v1.mail-core.reference-runtime-smoke`

This child exists to close the v1 root admission blocker: prove the reference deployment can run real mail daemons and pass a live mail-flow smoke instead of merely modeling daemon contracts.

Scope is deliberately narrow:

- reference Compose runtime wiring for Postfix, Dovecot, Rspamd, and selected webmail visibility
- seeded reference fixture data for `example.test` smoke accounts and alias
- executable runtime smoke harness
- contract tests that prevent the daemon services and smoke coverage from silently disappearing
