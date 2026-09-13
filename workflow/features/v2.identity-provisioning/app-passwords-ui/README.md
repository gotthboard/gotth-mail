# App passwords, Dovecot verifier integration, identity UI

ID: `v2.identity-provisioning.app-passwords-ui`

State: `in_progress`

Canonical state lives in `workflow.toml`. This folder holds scoped evidence, review notes, and postmortems only.

## Admitted scope

- durable opaque public IDs and separate human labels
- one-time opaque secrets with verifier-only storage
- at most eight active credentials per mailbox
- atomic PostgreSQL credential/success-audit admission
- bounded Dovecot verification and post-commit/startup projection
- runtime use of the configured identity service
- honest read-only identity status while OIDC subject-to-mailbox/role binding
  remains in the dependent live-Authentik slice

The legacy browser SCIM shortcut and bearer-header-dependent HTML mutation
forms are outside the admitted design and must be removed. The real scoped API
and `gotth-scim` endpoint remain authoritative.
