# GopherMailForge PRD — v5 Notifications

## Goal

v5 implements the notification backend plugin seam. Telegram is the first required implementation. Notifications may later include email and webhook. Messaging transports can deliver alerts and approval prompts, but the control plane remains the authority.

## Scope

### v5.1 Notification plugin: Telegram

- Telegram notification plugin container.
- gRPC notification backend implementation.
- Service identity authentication.
- Health/version/capability RPCs.
- Operational alerts for:
  - doctor failures
  - certificate renewal failures
  - backup verification failures
  - queue/deferred-mail alerts
  - abuse/rate-limit alerts
  - deployment status changes
  - plugin health failures

### v5.2 Read-only Telegram commands

- Doctor summary.
- Queue summary.
- Domain health.
- Backup status.
- Deployment status.
- Plugin health status.

Read-only commands must still authenticate the Telegram actor and audit the request.

### v5.3 Approval workflows

Only after policy/audit paths are proven:

- approve config apply
- approve DKIM rotation
- approve queue flush/retry
- approve rollback
- approve break-glass use

Rules:

- Telegram carries the prompt.
- Core decides authorization.
- Core validates confirmation.
- Approval prompts include request/correlation ID, actor, action, resource, expiry, and single-use confirmation binding.
- Core rejects stale, replayed, mismatched, or expired approvals.
- Core performs mutation.
- Core writes audit event.
- Telegram never mutates state directly.

### v5.4 Notification plugin safety

- Telegram actor-to-identity mapping.
- No authorization by chat membership alone.
- Every Telegram-triggered action audited.
- No secrets in Telegram messages.
- No full tokens, private keys, passwords, or unredacted before/after values.
- Failure to deliver notification must be visible in core status.

### v5.5 Additional notification targets

After Telegram proves the seam:

- email notification backend
- webhook notification backend
- Slack/Discord/etc only if justified

## Non-goals

- No Telegram-as-authority.
- No unaudited bot commands.
- No broad remote shell over chat.
- No notification plugin bypassing core policy.

## Acceptance criteria

- Telegram notification plugin runs as a separate Docker container.
- Telegram plugin communicates over gRPC/protobuf.
- Telegram plugin passes health/version/capability checks.
- Operational alerts are delivered through Telegram without exposing secrets.
- Read-only Telegram commands return bounded summaries.
- Every Telegram request is mapped to an identity and audited.
- Approval workflows, when enabled, use core authorization/confirmation/mutation/audit paths and reject stale, replayed, mismatched, or expired approvals.

## Mandatory OpenPGP signing for email notifications

Any email notification backend introduced in v5 must OpenPGP-sign every outbound email notification with the responsible user or system notification identity before delivery. Telegram/webhook transports may use their own authenticated transport semantics, but email output is never exempt from the global OpenPGP signing invariant.

Required behavior:

- unsigned email notifications are rejected before delivery;
- signing key lookup, fingerprint, signature status, and failure reason are auditable;
- per-user notification emails use that user's signing identity when the message asserts that user as sender;
- system notifications use a configured system notification signing identity;
- key rotation/revocation must not allow fallback to unsigned mail;
- verification tests must prove that outbound notification email contains an OpenPGP/MIME signature and that missing/revoked keys block send.


The signature requirement is not merely provenance for a domain or server. Verification must answer exactly which configured user identity signed the message. If the signer cannot be mapped to the asserted From/Sender identity and active user/key binding, the message is treated as unsigned/invalid.
