# GOTTH Mail PRD — 1.0 release line

## Goal

GOTTH Mail `1.0.0` is the first stable release of the complete, deployable mail
stack. Foundation, mail transport, identity and provisioning, operations,
webmail, notifications, deployment, recovery, and acceptance are workstreams
inside that one release line. They are not separate product major versions.

## Published versions

- `1.0.0-alpha.N` identifies an incomplete integration build. An alpha may be
  useful for development, but required workstreams or production evidence may
  still be absent.
- `1.0.0-beta.N` identifies a feature-complete integrated stack undergoing
  production hardening and owner acceptance. A beta may contain defects but may
  not omit a required 1.0 workstream.
- `1.0.0` is the first stable release.

No `0.x`, bare `v0` through `v5`, release-candidate, or stable tag is part of
the current product release contract. Existing `v0.*` through `v5.*` workflow
IDs and document filenames are retained as historical capability identifiers;
they do not assert published versions.

## Stable 1.0 scope

Stable `1.0.0` requires all of the following:

1. the foundation and reference deployment workstream;
2. production Postfix, Dovecot, Rspamd, DNS, TLS, and delivery proof;
3. Authentik-backed web login and SCIM provisioning using the admitted
   `gotth-oidc` and `gotth-scim` libraries through consumer-owned persistence,
   authorization, audit, and product adapters;
4. durable administration, including one host-owned Extensions surface for
   setup, testing, enable/disable, update, rollback, and audit; Mailu
   adoption/import, backup, isolated restore, abuse controls, and diagnostics;
5. production IMAP/SMTP webmail with the required exact-sender OpenPGP policy;
6. notification delivery, approvals, identity binding, and key lifecycle;
7. container deployment, upgrade, rollback, security, accessibility,
   monitoring, and operator handoff evidence; and
8. explicit owner acceptance of the complete deployed stack.

## GOTTH identity libraries

`gotth-oidc` owns hardened OIDC protocol behavior. GOTTH Mail owns atomic
attempt consumption, browser binding, users, sessions, authorization, and
runtime provider configuration.

`gotth-scim` owns RFC 7643/7644 protocol, validation, HTTP, reconciliation, and
store conformance behavior. GOTTH Mail owns bearer authentication,
provisioning scope, a durable transactional store adapter, mailbox/domain
policy, password delegation, audit, daemon synchronization, and session
effects.

The 1.0-alpha development line has removed the duplicate in-tree OIDC and SCIM
protocol implementations in favor of the pinned libraries while preserving
the public routes. This is implementation progress, not a stable claim:
operator-reviewed legacy identity adoption, live Authentik lifecycle,
backup/restore, and complete release evidence still gate promotion.

The integration contract composes them through an exact durable relation:
verified OIDC issuer/subject plus verified email must identify one active SCIM
User `externalId` and mailbox projection. Sessions foreign-key that relation;
SCIM deprovisioning revokes them. Authentik-specific token claims are not a
shortcut around the libraries or product authorization state.

## GOTTH Extensions management

Stable 1.0 adopts an exact reviewed `gotth-extensions` foundation revision and
reconciles the existing Mail plugin control pieces with its manifest, grant,
negotiation, lifecycle, handshake, and health contracts. Concrete mechanisms
remain in independent `gotth-extension-<slug>` repositories and retain their
seam-specific protocols.

The Mail administrator owns one native Extensions page. Extensions cannot
inject markup, scripts, templates, styles, redirects, or arbitrary form
actions. Mail owns the registry, authorization, CSRF and confirmation,
write-only encrypted secrets, process supervision, mutation, audit, update,
and rollback policy. No shared cross-product control-plane authority is
introduced.

## Acceptance

- Every published pre-stable version is an immutable `1.0.0-alpha.N` or
  `1.0.0-beta.N` tag.
- Beta cannot begin while a required workstream is incomplete.
- Stable cannot be tagged while a required feature, migration, deployment,
  restore, security, accessibility, monitoring, or owner-acceptance gate is
  blocked.
- The public binary version and annotated Git tag agree exactly, apart from the
  tag's required `v` prefix.
- `gotth-oidc` and `gotth-scim` are pinned to reviewed immutable commits or
  tags; floating branches are forbidden in admitted builds.
- Library license and independent release gates remain explicit. Consumer use
  does not fabricate a library release.
- Beta cannot begin until the Extensions administrator proves safe setup,
  test, enable, disable, update, rollback, redaction, accessibility, and
  failure behavior against at least one real independently packaged extension.
