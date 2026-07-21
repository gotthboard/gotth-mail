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

The target implementation contract is [Exact Sender Identity Binding for OpenPGP/MIME Signed Email](../reference/openpgp-exact-sender/draft-hunn-openpgp-exact-sender-signatures-01.md). This configured system-notification adapter is a bounded subset with exact signing/verification and local structured delivery evidence; it does not claim profile conformance. Recorded public-key discovery, complete rotation/deletion/recovery policy, per-user/role/delegation identity mapping, and message-context authorization remain unimplemented. Notification identity history, downgrade detection, key-rotation continuity, and forensic export behavior must conform to [Operational Identity History and Audit Indexing for Exact Sender Binding](../reference/openpgp-exact-sender/draft-hunn-exact-sender-operational-identity-history-00.md) where implemented.

Any email notification backend introduced in v5 must OpenPGP-sign every outbound email notification with the responsible user or system notification identity before delivery. Telegram/webhook transports may use their own authenticated transport semantics, but email output is never exempt from the global OpenPGP signing invariant. `notifyruntime.SignedEmailBackend` implements the configured system-identity adapter. It sanitizes the alert, reloads and resolves exact sender lifecycle state for each delivery, constructs RFC 2047/quoted-printable seven-bit MIME with a stable alert-derived Message-ID, signs through `webmail.OpenPGPMIMESigner`, requires one canonical headerless detached-signature armor block containing exactly one SHA-256 packet as advertised by `micalg=pgp-sha256`, cryptographically verifies that hash over the exact raw signed entity through `webmail.OpenPGPMIMEVerifier`, and passes only those verified bytes to a trusted local SMTP relay. Parser shape or a generic cryptographic-validity result alone is not an admission check. Key types whose maintained signing path cannot emit SHA-256 are rejected during configuration and remain permanent fail-closed delivery errors after runtime reload.

`gmf-plugin` exposes this adapter only as the distinct `signed-email-notification-sink` mechanism. The Telegram mechanism retains its existing behavior. The signed-email process requires these settings together:

- `GMF_NOTIFICATION_EMAIL_FROM`
- `GMF_NOTIFICATION_EMAIL_TO`
- `GMF_NOTIFICATION_EMAIL_SIGNING_FINGERPRINT`
- `GMF_NOTIFICATION_EMAIL_PRIVATE_KEY_FILE`
- `GMF_NOTIFICATION_EMAIL_SMTP_ADDR` as `host:port`

Startup validates complete configuration. Startup and every delivery load a bounded regular private-key file that is not group/world accessible and require exactly one matching entity, exactly one matching sender user ID, usable unencrypted private signing material, and non-revoked/non-expired identity and key state. Invalid or partial configuration aborts startup; later lifecycle/key-file drift blocks that delivery. `GMF_NOTIFICATION_EMAIL_SMTP_ADDR` is limited to loopback/private IPs or a single-label local service name because the transport has no remote TLS/authentication policy. Literal public IPs and dotted hostnames are rejected; a single-label name delegates trust to the deployment's local/container resolver. This first configured adapter intentionally has no prompt capability.

The adapter is not yet selected by the control-plane application. `cmd/gophermailforge` still builds the default first-mechanism registry, which excludes signed email, and no core alert dispatcher routes to the explicit registration. That routing/selection work remains a feature blocker; the child-process integration proves the standalone plugin adapter, not an end-to-end application notification path.

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
sanitize and bound alert
  -> resolve signing identity and usable lifecycle state
  -> build seven-bit transport-safe MIME with stable Message-ID
  -> OpenPGP/MIME sign with a packet hash verified as SHA-256
  -> verify pgp-sha256 over the exact raw entity plus sender/From/Message-ID/Date/Subject binding
  -> hand verified bytes to a trusted local SMTP relay
  -> return typed evidence for gRPC and core/SQL persistence
```

Failure states:

- `signing_key_missing`
- `signing_key_revoked`
- `signing_key_expired`
- `signing_identity_disabled`
- `signing_identity_ambiguous`
- `signing_identity_unmapped`
- `signing_identity_mismatch`
- `openpgp_sign_failed`
- `openpgp_verification_failed`
- `smtp_rejected`
- `smtp_unavailable`
- `smtp_delivery_ambiguous`

All failure states block delivery and surface as bounded delivery results; dependency error strings and sink-supplied gRPC descriptions/details are not returned through the plugin seam. Both alert and prompt RPC failures are mapped to an allowed gRPC code with fixed server-owned text. Secret markers in alert text cause whole-field redaction before MIME construction rather than partial value substitution. Secret-bearing IDs, classes, correlation IDs, and resource types are rejected before bounding. Detail keys are checked in their complete normalized form before truncation, and a bounded-key collision cannot replace an existing redaction. Successful typed evidence contains transport, Message-ID, generation time, From/Sender, signing fingerprint, sender identity ID/class, policy version, lifecycle reference, `valid_exact_sender`, and workflow. Every evidence field is independently grammar- and secret-checked before memory, SQL, or gRPC use. The adapter carries that type over gRPC, and the SQL recorder separately persists it; control-plane composition remains unfinished. The email backend must not send unsigned mail to preserve alert delivery convenience. That would be security theater.

The additive evidence migration does not rewrite the baseline schema. Runtime admission validates every recorded migration before applying a missing known upgrade: baseline rows must exist, all known rows must be clean with exact checksums, and unknown/future versions are rejected. The immutable `d432e5b` baseline checksum fixture prevents accidental history edits, while the canonical `0002_notification_delivery_evidence` SQL file is parity-checked against the registered runtime SQL, identifier, and checksum. A pre-existing wrong-shaped evidence column fails rather than being certified by `IF NOT EXISTS`. Migration and isolated-restore transactions execute with `SET LOCAL search_path = public, pg_catalog`; restore readback uses explicit `public` relations. `MigrateEmptySQL` rejects any existing user relation in `public` before DDL, so a hostile caller search path or shadow schema cannot redirect the restore target.

The configured adapter represents one system notification identity. Core routing/selection, per-user/role/delegation identity mapping, message-context authorization, recorded public-key discovery, complete rotation/deletion/recovery policy, and production key custody remain explicit work. The adapter and feature do not yet claim application integration or full profile conformance.


The signature requirement is not merely provenance for a domain or server. Verification must answer exactly which configured user identity signed the message. If the signer cannot be mapped to the asserted From/Sender identity and active user/key binding, the message is treated as unsigned/invalid.
