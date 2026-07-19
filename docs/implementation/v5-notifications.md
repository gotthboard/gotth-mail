# Implementation Spec — v5 Notifications

Source PRD: [PRD-v5-notifications.md](../prd/PRD-v5-notifications.md)
Source architecture: [architecture/v5-notifications.md](../architecture/v5-notifications.md)

## Goal

Implement the notification backend plugin seam with Telegram as the first required implementation. Notification transports deliver alerts and approval prompts; the control plane remains the authority.

## Notification protobuf

Package: `gophermailforge.notification.v1`

```proto
service NotificationBackend {
  rpc Health(HealthRequest) returns (HealthResponse);
  rpc Version(VersionRequest) returns (VersionResponse);
  rpc Capabilities(CapabilitiesRequest) returns (CapabilitiesResponse);
  rpc SendAlert(SendAlertRequest) returns (SendAlertResponse);
  rpc SendPrompt(SendPromptRequest) returns (SendPromptResponse);
}
```

Every RPC requires plugin service identity authentication, correlation ID metadata, deadlines, and structured errors.

## Telegram plugin

Telegram runs as a separate Docker container. The current reference container is `telegram-notification-sink`, exposed as `notification-plugin:9443` on the existing authenticated `PluginControl` gRPC seam with notification health/version/capabilities and the notification-specific `NotificationBackend.SendAlert`/`SendPrompt` protobuf service. The current sink accepts sanitized alert/prompt payloads inside the repo-owned container smoke; live Telegram API delivery remains required before this is a real Telegram backend. The plugin does not read core DB state directly and never mutates canonical state.

Telegram plugin config:

- bot token secret reference
- allowed chat IDs or mapping source
- delivery mode
- rate-limit settings
- redaction mode

Secrets must be provided through explicit secret mounts or environment references, not broad filesystem mounts.

## Alerts

Required alert classes:

- doctor failures
- certificate renewal failures
- backup verification failures
- queue/deferred-mail alerts
- abuse/rate-limit alerts
- deployment status changes
- plugin health failures

No alert includes secrets, full tokens, private keys, passwords, or unredacted before/after values.

Delivery result state:

```text
pending -> delivered
        -> failed_retryable
        -> failed_permanent
```

Notification delivery failures are recorded in core status and visible to operators. Configured SQL deployments store delivery records in `notification_deliveries`; operators can read bounded delivery status through `GET /api/v1/notifications/deliveries` and `GET /api/v1/notifications/deliveries/{alert_id}` with `notification:read` authorization. The notification backend gRPC seam accepts delivery status from the sink but does not grant state mutation authority to the plugin.

## Read-only commands

Supported Telegram commands:

- doctor summary
- queue summary
- domain health
- backup status
- deployment status
- plugin health status

Command flow:

```text
telegram update -> authenticate actor -> map identity -> authorize read action -> query bounded summary -> audit request -> send response
```

Read-only responses must be bounded summaries. No raw logs, secrets, private keys, full tokens, or broad shell output. The local command core maps the transport actor, authorizes the command-specific read action, calls only a `CommandProvider` summary interface, redacts/bounds returned text, and audits denied, failed, and successful attempts. `notifyruntime.RuntimeCommandProvider` supplies real bounded summaries from existing doctor, queue, domain, backup, deployment, and plugin state objects without invoking shell commands or broad logs.

## Actor mapping

Telegram actor mapping is explicit. Chat membership is not authorization. Configured SQL deployments store mappings in `notification_actor_mappings` and require an exact `(transport, external_actor_id)` mapping to an `authz.Actor` before command or approval handling can proceed.

Mapping sources may include:

- configured chat/user IDs
- linked GopherMailForge user accounts
- Authentik identities
- explicit combination of the above

Approval workflows cannot be enabled until mapping is configured and verified.

The local SQL core now provides this mapping store, and the local read-only command dispatcher consumes it. Runtime summary providers exist for configured state objects. The Telegram update receiver core now parses Telegram-shaped command/callback updates and routes them into `CommandService` and `SQLApprovalStore`; live Telegram webhook/API delivery remains pending.

## Approval workflow

Supported approvals:

- config apply
- DKIM rotation
- queue flush/retry
- rollback
- break-glass use

Configured SQL deployments store prompt bindings in `notification_approvals`; confirmation accepts only the exact original transport actor, mapped actor, action, resource, request hash, and unexpired prompt ID. Mismatched, replayed, and expired confirmations fail closed before any mutation path can run.

Prompt record fields:

- `id`
- `correlation_id`
- `actor_id`
- `action`
- `resource_type`
- `resource_id`
- `preview_hash` or request hash where applicable
- `confirmation_binding_hash`
- `expires_at`
- `used_at`
- `status`: `pending`, `approved`, `rejected`, `expired`, `mismatch`

Flow:

```text
create prompt with one-time binding nonce -> deliver prompt -> receive response -> authenticate Telegram actor -> map identity -> verify single-use binding -> authorize action -> validate confirmation -> perform mutation -> audit result
```

The prompt displays or carries only the one-time binding nonce needed for the operator response. Core stores only `confirmation_binding_hash`; responses that do not prove the binding are rejected before authorization or mutation.

Rejection cases:

- stale prompt
- replayed prompt
- mismatched actor
- mismatched action/resource
- expired prompt
- changed preview/request hash
- unauthorized actor

Telegram carries the prompt only. Core decides authorization, validates confirmation, performs mutation, and writes audit events. The current local implementation receives approval callbacks, validates durable SQL prompt binding, and can execute only the narrow approved queue mutation set through `notifyruntime.ApprovalExecutor` (`queue:flush`, `queue:retry`). There is no generic chat-to-shell or arbitrary mutation registry.

## Non-goals

- no Telegram-as-authority
- no unaudited bot commands
- no broad remote shell over chat
- no notification plugin bypassing core policy

## Additional backends

Email and webhook notification backends may be added after Telegram proves the seam. Slack/Discord/etc require explicit justification. All remain notification backends, not authorities.

## Verification

Required tests:

- Telegram plugin runs as separate Docker container
- plugin communicates over gRPC/protobuf
- authenticated health/version/capability checks pass
- unauthenticated plugin calls fail
- alerts deliver without exposing secrets
- delivery failures are visible in core status
- read-only commands authenticate actor, map identity, authorize read, audit request, and return bounded summaries
- chat membership alone does not authorize commands or approvals
- approval workflows use core authorization/confirmation/mutation/audit paths
- stale/replayed/mismatched/expired/changed-hash/bad-binding approvals are rejected
- Telegram plugin never mutates state directly
- no broad remote shell over chat
- `git diff --check`
- `go test ./...`

## Mandatory OpenPGP signing for email notifications

Implementation must conform to [Exact Sender Identity Binding for OpenPGP/MIME Signed Email](../reference/openpgp-exact-sender/draft-hunn-openpgp-exact-sender-signatures-01.md). Notification identity history, downgrade detection, key-rotation continuity, and forensic export behavior must conform to [Operational Identity History and Audit Indexing for Exact Sender Binding](../reference/openpgp-exact-sender/draft-hunn-exact-sender-operational-identity-history-00.md) where implemented.

Any email notification backend introduced in v5 must OpenPGP-sign every outbound email notification with the responsible user or system notification identity before delivery. Telegram/webhook transports may use their own authenticated transport semantics, but email output is never exempt from the global OpenPGP signing invariant.

Required behavior:

- unsigned email notifications are rejected before delivery;
- signing key lookup, fingerprint, signature status, and failure reason are auditable;
- per-user notification emails use that user's signing identity when the message asserts that user as sender;
- system notifications use a configured system notification signing identity;
- key rotation/revocation must not allow fallback to unsigned mail;
- verification tests must prove that outbound notification email contains an OpenPGP/MIME signature, resolves to exactly one authorized sender identity, and that missing/revoked/expired/ambiguous/mismatched keys block send.

## OpenPGP email signing contract

Email notification signing contract:


Identity binding requirement: verification must resolve the OpenPGP signing key fingerprint to exactly one configured active user or system notification identity, then confirm that identity is allowed to assert the message `From`/`Sender`. Ambiguous, shared, revoked, expired, disabled, or unmapped keys fail closed.

```text
build bounded notification MIME -> resolve signing identity -> verify key usable -> OpenPGP/MIME sign -> hand to mail transport -> audit fingerprint/signature status
```

Failure states:

- `signing_key_missing`
- `signing_key_revoked`
- `signing_key_expired`
- `signing_identity_mismatch`
- `openpgp_sign_failed`

All failure states block delivery and surface in core status. The email backend must not send unsigned mail to preserve alert delivery convenience. That would be security theater.


The signature requirement is not merely provenance for a domain or server. Verification must answer exactly which configured user identity signed the message. If the signer cannot be mapped to the asserted From/Sender identity and active user/key binding, the message is treated as unsigned/invalid.
