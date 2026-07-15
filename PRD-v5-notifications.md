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
- Approval workflows, when enabled, use core authorization/confirmation/mutation/audit paths.
