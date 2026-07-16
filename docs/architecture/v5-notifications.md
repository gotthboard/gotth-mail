# Architecture — v5 Notifications

Source PRD: [PRD-v5-notifications.md](../prd/PRD-v5-notifications.md)

## Goal

v5 implements the notification backend plugin seam. Telegram is the first required implementation. Notification transports may deliver alerts and approval prompts; the control plane remains the authority.

## Notification plugin topology

Telegram runs as a separate Docker container and implements the notification backend gRPC/protobuf contract.

The plugin exposes:

- health RPC
- version RPC
- capability RPC
- send alert RPC
- send prompt RPC where approval workflows are enabled

The plugin authenticates with service identity credentials.

## Alert architecture

Telegram receives high-priority operational alerts for:

- doctor failures
- certificate renewal failures
- backup verification failures
- queue/deferred-mail alerts
- abuse/rate-limit alerts
- deployment status changes
- plugin health failures

No alert includes secrets, full tokens, private keys, passwords, or unredacted before/after values.

Notification delivery failures are recorded in core status. A failed Telegram delivery must be visible to operators without granting the Telegram plugin authority over state.

## Read-only command architecture

Read-only Telegram commands:

- doctor summary
- queue summary
- domain health
- backup status
- deployment status
- plugin health status

Read-only commands still authenticate the Telegram actor, map actor to identity, and write an audit event.

## Approval workflow architecture

Approval workflows may be enabled only after policy/audit paths are proven.

Supported approval prompts:

- config apply
- DKIM rotation
- queue flush/retry
- rollback
- break-glass use

Rules:

- Telegram carries the prompt.
- Core decides authorization.
- Core validates confirmation.
- Prompt includes request/correlation ID, actor, action, resource, expiry, and single-use binding.
- Core rejects stale, replayed, mismatched, or expired approvals.
- Core performs mutation.
- Core writes audit event.
- Telegram never mutates state directly.

## Actor mapping

Telegram actor mapping is explicit. Chat membership is not authorization.

Possible configured identity sources may include chat IDs, linked user accounts, Authentik identities, or a combination. The chosen mapping must be explicit before approval workflows are enabled.

## Additional notification targets

After Telegram proves the seam:

- email backend
- webhook backend
- Slack/Discord only if justified

These remain notification backends, not authorities.

## Non-goals

- no Telegram-as-authority
- no unaudited bot commands
- no broad remote shell over chat
- no notification plugin bypassing core policy

## Verification gates

- Telegram plugin runs as separate Docker container
- plugin communicates over gRPC/protobuf
- plugin passes authenticated health/version/capability checks
- alerts deliver without exposing secrets
- notification delivery failures are visible in core status
- read-only commands return bounded summaries
- every Telegram request maps to identity and audit event
- approval workflows use core authorization/confirmation/mutation/audit paths
- approval workflows reject stale/replayed/mismatched/expired approvals

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
