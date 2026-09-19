# Architecture — v5 Notifications

Source PRD: [PRD-v5-notifications.md](../prd/PRD-v5-notifications.md)

## Goal

v5 implements the notification backend plugin seam. Telegram is the first required implementation. Notification transports may deliver alerts and approval prompts; the control plane remains the authority.

## Notification plugin topology

Telegram runs as a separate Docker container and implements the notification backend gRPC/protobuf contract. Core accepts notification endpoints only on loopback or as absolute sockets below `/run/gotth-mail-plugins/`; the reference containers share that socket directory. Service credentials are never sent over an arbitrary private/container TCP network.

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

The target architecture is [Exact Sender Identity Binding for OpenPGP/MIME Signed Email](../reference/openpgp-exact-sender/draft-hunn-openpgp-exact-sender-signatures-01.md). The configured system-notification adapter below is a bounded subset: it implements one system sender's signing, exact-entity verification, per-delivery lifecycle admission, and local audit record. It does not claim profile conformance. Recorded public-key discovery, complete rotation/deletion/recovery policy, per-user/role/delegation identity mapping, and message-context authorization remain required before such a claim. Any identity history, search, audit indexing, downgrade detection, key rotation continuity, or forensic export behavior must conform to [Operational Identity History and Audit Indexing for Exact Sender Binding](../reference/openpgp-exact-sender/draft-hunn-exact-sender-operational-identity-history-00.md).

Any email notification backend introduced in v5 must OpenPGP-sign every outbound email notification with the responsible user or system notification identity before delivery. Telegram/webhook transports may use their own authenticated transport semantics, but email output is never exempt from the global OpenPGP signing invariant.

Signed email is a distinct, explicitly configured notification plugin (`signed-email-notification-sink`), not hidden behavior inside the Telegram sink. Its opt-in Compose profile runs a separate real plugin process. The process composes one configured system sender identity from a bounded private-key file, the real OpenPGP/MIME signer and exact-sender verifier, and the real SMTP submitter. An absent or incomplete email configuration prevents that plugin from starting; it never falls back to the local/Telegram sink or unsigned SMTP.

Core explicitly selects exactly one configured Telegram or signed-email adapter and composes it with the SQL delivery recorder. Signed email remains alert-only; selecting it while enabling a Telegram webhook fails startup.

The release boundary is:

```text
sanitize alert
  -> resolve exactly one active sender/key binding
  -> build RFC 2047/quoted-printable seven-bit MIME with stable Message-ID
  -> OpenPGP/MIME sign and require the signature packet hash to match pgp-sha256
  -> require one canonical headerless armor block with exactly one SHA-256 signature packet
  -> cryptographically verify SHA-256 over the exact raw signed entity, fingerprint, From, Message-ID, Date, and Subject binding
  -> submit the verified bytes to a trusted local SMTP relay
  -> return structured bounded delivery evidence for core/SQL persistence
```

The configured private-key file is deliberately narrow: one matching unencrypted signing entity, bounded file size, exact From user-ID binding, and active/non-revoked/non-expired signing material. The file is reloaded and lifecycle-validated for every delivery, so expiration, revocation, disablement, or replacement after process startup fails closed. Encrypted-key unlock services, HSM/KMS custody, complete rotation/deletion/recovery policy, per-user/role/delegation identity selection, message-context authorization, and public-key discovery are separate work; their absence cannot enable unsigned fallback in this adapter.

SMTP acceptance is an explicit boundary. This adapter accepts only a loopback/private address or single-label local service name because `NetSMTPSubmitter` deliberately has no remote TLS/authentication policy; literal public IPs and dotted hostnames are rejected. A single-label name delegates trust to the deployment's local/container resolver and must resolve to the intended trusted relay. Permanent SMTP rejection is not retryable, pre-acceptance transport failure is retryable, and loss of the reply at the DATA acceptance boundary is reported as `smtp_delivery_ambiguous` and is not blindly retried. A failed QUIT after successful DATA acceptance does not create a duplicate-delivery retry.

Successful adapter metadata is structured rather than packed into prose: transport, Message-ID, generation time, From/Sender, signing fingerprint, sender identity ID/class, policy version, lifecycle reference, verification result, and workflow are carried over gRPC. Each evidence field is admitted against a field-specific grammar and secret check before memory, SQL, or gRPC use; an unsafe field is dropped rather than persisted or echoed. The configured control-plane service persists the typed result through the SQL recorder.

Failure reasons use a bounded machine-readable allowlist. Sink-supplied gRPC descriptions and details are discarded for both alert and prompt RPCs and rebuilt from fixed server-owned status text; arbitrary sink/dependency strings cannot cross the plugin seam. Secret-marked alert fields are redacted as a whole rather than partially parsed, including JSON-quoted, multiword, Unicode-whitespace, bearer, and armored-private-key forms. Secret markers in alert IDs, classes, correlation IDs, and resource types are rejected before bounding. Complete normalized detail keys are checked before truncation, and deterministic bounded-key collision handling preserves a prior redaction rather than allowing a later safe-looking value to replace it.

The SQL evidence migration is additive and lineage-checked. The immutable `d432e5b` baseline definitions remain unchanged; migration admission enumerates the complete ledger and rejects missing baselines, dirty or checksum-mismatched known rows, and unknown/future versions before applying a missing known upgrade. The registered runtime migration and canonical SQL file share one identifier, SQL body, and checksum. Migration and isolated-restore transactions pin `search_path` to `public, pg_catalog`, restore readback is schema-qualified, and an empty restore target means no existing user relations in `public`. A caller-controlled shadow schema cannot capture migration DDL or restored state.

Required behavior:

- unsigned email notifications are rejected before delivery;
- signing key lookup, fingerprint, signature status, and failure reason are auditable;
- per-user notification emails use that user's signing identity when the message asserts that user as sender;
- system notifications use a configured system notification signing identity;
- key rotation/revocation must not allow fallback to unsigned mail;
- verification tests must prove that outbound notification email contains an OpenPGP/MIME signature, survives SMTP canonicalization, and that missing/revoked/expired/ambiguous/disabled/mismatched keys block send before SMTP.

This slice does not implement per-user/role/delegation notification identity selection, public-key discovery, or full rotation/deletion/recovery policy. Those remain later release scope; the system-identity adapter must not be used to claim user identity or full profile conformance.


The signature requirement is not merely provenance for a domain or server. Verification must answer exactly which configured user identity signed the message. If the signer cannot be mapped to the asserted From/Sender identity and active user/key binding, the message is treated as unsigned/invalid.
