# Implementation Spec — v1 Mail Core

Source PRD: [PRD-v1-mail-core.md](../prd/PRD-v1-mail-core.md)
Source architecture: [architecture/v1-mail-core.md](../architecture/v1-mail-core.md)

## Goal

Implement the real mail control path: Postfix, Dovecot, and Rspamd contracts; generated daemon config; DNS/TLS/ACME guidance; doctor; lookup debugger; mail flow trace; queue visibility; smoke tests; snapshots; and first mechanism-plugin containers.

Mail delivery and daemon lookups must not depend on Authentik availability.

## Internal daemon API

Internal daemon APIs are core contracts, not plugin seams. v1 uses HTTP/JSON internal APIs as the canonical wire contract. Daemon-native map/protocol adapters may be generated or configured, but they must call or preserve the same documented decision semantics.

All daemon API responses include:

- correlation ID
- decision enum
- reason code
- safe diagnostic message

Never return fake success for lookup failure.

## Postfix contract

Required lookups:

```text
GET /internal/v1/postfix/domains/{domain}
GET /internal/v1/postfix/recipients/{address}
GET /internal/v1/postfix/mailboxes/{address}
GET /internal/v1/postfix/aliases/{address}
POST /internal/v1/postfix/sender-login
POST /internal/v1/postfix/sender-policy
GET /internal/v1/postfix/rate-limit/{sender}
GET /internal/v1/postfix/transport/{domain}
```

Decision enum:

```text
ok
not_found
reject
defer
error
```

Sender login request:

```json
{
  "sasl_username": "user@example.test",
  "mail_from": "user@example.test",
  "client_ip": "192.0.2.10"
}
```

Alias response:

```json
{
  "decision": "ok",
  "targets": ["target@example.test"],
  "reason": "alias_expanded"
}
```

Failure rules:

- disabled domain -> `reject`
- unknown recipient -> API returns `not_found`; daemon adapters may map that to the daemon-specific reject behavior configured for Postfix
- database unavailable -> `defer`
- malformed daemon request -> `error`

Queue admission must prove unchanged original/final delivery pairs against the
already-loaded expansion roots. If the original address is an exact alias, a
catch-all match, or a self-cycle root, equality is not terminal delivery and the
message is rejected before `QueueStore.Register`. If no loaded root exists, the
unchanged pair remains a cheap direct leaf and no graph walk or SQL expansion is
added for that case. Unequal pairs retain the existing complete-reachable-graph
walk.

## Per-domain outbound scope

Persist `domains.outbound_scope` as the closed enum `unrestricted` or
`same_domain_only`, with a database default of `unrestricted`, plus a monotonic
`outbound_policy_revision`. Reject unknown values at configuration, API, and
database boundaries. Existing rows migrate to `unrestricted`; migration alone
must not change delivery behavior.

Add the internal decision contract:

```text
POST /internal/v1/postfix/outbound-policy
```

A submission request carries the authenticated SASL identity or durable
system-sender identity, envelope sender, one candidate resolved envelope
recipient, and opaque identifiers for every local expansion source. Before a
final queue becomes deliverable, persist and bind its immutable complete original
final-envelope recipient set plus authoritative expansion/source object IDs and
digests to the Postfix queue ID. A transport request carries the queue ID and
delivery-request identity; its current qmgr recipient batch, caller-supplied
domains and message `From` are not authority. The server loads the full bound set
and resolves current mailbox, envelope-sender authorization, system binding,
expansion objects, governing domains, and revisions itself. Missing, mismatched,
renamed or removed bindings defer. No concurrent queue scan substitutes for the
bound set.

Decision reason codes are closed and stable:

```text
ok / outbound_scope_unrestricted
ok / same_domain
reject / recipient_domain_forbidden
reject / cross_domain_policy_conflict
defer / recipient_domain_policy_hold
defer / outbound_policy_unavailable
```

Normalize both domains to lowercase ASCII A-label form, remove one terminal
dot, and reject malformed or empty domains. Permit only exact equality for
`same_domain_only`; subdomains and other hosted domains are forbidden. Build
the governing set from the authenticated mailbox, admitted envelope sender,
system-sender binding, and each local alias/forward/list/catch-all source. A
recipient must equal every restricted member. Distinct restricted domains in
one governing set produce `reject / cross_domain_policy_conflict`. Apply the
decision to every final recipient after alias, forward, list, BCC, and catch-all
expansion. Expansion cycles, excessive fan-out, missing governing objects, or
unavailable policy state defer rather than permit delivery.

Postfix must invoke the policy during authenticated submission at `RCPT TO`
and immediately before final transport. Map a forbidden SMTP recipient to
`550 5.7.1`; map unavailable policy state to `451 4.3.0`. Webmail and product
API submission resolve the complete recipient set first and reject the whole
request before queueing if any recipient is forbidden. Queue retry, manual
flush, replay, and restored queues re-evaluate the current persisted policy;
the policy captured when a message was accepted is not an authorization grant.
The final delivery-agent path must perform that recheck for each qmgr delivery
attempt before remote DATA, including retry after a remote 4xx.

At transport, evaluate every recipient in the immutable bound final-envelope
set on every qmgr request. A newly forbidden bound recipient durably commits
`hold_required` and returns `defer / recipient_domain_policy_hold`, not a
permanent failure that would generate an external DSN. The current and every
later batch for that queue tempfails before network. After the active request
returns, the idempotent privileged reconciler places the entire original Postfix
queue message on hold, verifies it, and records the queue ID, policy revision,
reason and hold state. Postfix has no honest per-recipient hold primitive, so one
forbidden bound recipient holds the whole message and may delay permitted
recipients. Diagnostics and activation preview must expose that consequence.

The generated Postfix configuration requires `enable_long_queue_ids = yes`.
Queue reconciliation reads structured queue metadata, verifies the expected
sender, arrival identity, and recipient set, invokes a dedicated privileged
helper equivalent to `postsuper -h <queue_id>` with one strictly validated ID
and no shell, then verifies that exact message is in the hold queue. Release is
an independent confirmed helper operation equivalent to
`postsuper -H <queue_id>`. The helper must not expose delete, expiry, arbitrary
selectors, `ALL`, raw arguments, or general command execution. A missing,
reused, mismatched, or changing queue record fails closed and remains an
operator-visible reconciliation error.

Notifications, autoresponders, DSNs, bounces, and other system-generated mail
must carry an admitted originating domain identity and use the same decision
contract. For non-null signed forwarding, use the configured local forwarding
identity as SMTP envelope sender and local DSN destination; never use the remote
original author. If the triggering envelope sender is null, keep the forwarded
delivery null and bounce-suppressed. Reject during the original SMTP transaction when possible. Otherwise
suppress the forbidden automatic external message, record a terminal
`policy_blocked` disposition, and emit no second bounce. No internal component,
administrator action, or notification plugin receives a bypass.

Changing from `unrestricted` to `same_domain_only` is a two-step operation:

1. preview the exact domain-policy revision and a digest plus bounded counts of
   affected aliases, forwards, and queued external recipients;
2. confirm that digest against the unchanged revision, update the policy and
   revision atomically, and audit the actor, old/new scope, digest, and counts.

Stale confirmation fails. The policy transaction commits before queue
reconciliation; final-transport checks therefore defer racing external
recipients while idempotent reconciliation places affected queue messages on
hold. Hold failures remain visible and retryable, never permissive. Changing
back to `unrestricted` is independently confirmed and audited; held mail
requires an explicit, separately authorized release. Audit records contain
addresses only where the existing audit-retention policy permits them and
never contain message bodies, credentials, or signing key material.

Required tests cover exact-domain acceptance; subdomain and other-hosted-domain
rejection; Unicode/IDNA and terminal-dot normalization; mixed-recipient SMTP
and atomic web/API behavior; alias/forward/list/BCC/catch-all expansion;
notifications, autoresponders, DSNs, and bounce-loop suppression; policy-store
failure; delegated cross-domain send-as; inbound-to-external forwarding; chained
cross-domain expansions; conflicting restricted governing domains; race with
activation; retry, flush, replay, restore, and final-handoff rechecks; whole-
message hold behavior for mixed-recipient queue files; stale preview rejection;
rollback without implicit release; idempotent hold reconciliation and failure
recovery; audit redaction; and proof that inbound mailbox delivery remains
accepted.

## Dovecot contract

Required lookups:

```text
POST /internal/v1/dovecot/passdb
GET  /internal/v1/dovecot/userdb/{address}
POST /internal/v1/dovecot/quota
GET  /internal/v1/dovecot/sieve/default/{address}
```

Passdb request:

```json
{
  "username": "user@example.test",
  "secret": "redacted-at-boundary",
  "protocol": "imap|submission"
}
```

Passdb behavior:

- app-password/mail-client token verifier is checked against the stored Authentik-compatible Django encoded verifier/hash string where applicable
- plaintext secret is never logged or audited
- OIDC session tokens are not accepted for IMAP/SMTP
- disabled mailbox returns explicit reject

Userdb response:

```json
{
  "decision": "ok",
  "home": "/mail/example.test/user",
  "uid": 5000,
  "gid": 5000,
  "quota_bytes": 1073741824
}
```

## Rspamd contract

Required lookups:

```text
GET /internal/v1/rspamd/local-domains
GET /internal/v1/rspamd/dkim/{domain}
POST /internal/v1/rspamd/signing-decision
POST /internal/v1/rspamd/rate-signal
```

DKIM key response must not expose private key material outside the minimum runtime path needed by Rspamd. Access must be auditable at the control-plane boundary.

## Generated daemon config

Renderers produce config for:

- front/proxy
- Postfix maps/config
- Dovecot auth/userdb/quota
- Rspamd local-domain/DKIM
- selected external webmail provider

Each generated file must include:

```text
# Generated by GOTTH Mail. Do not edit directly.
# Source: generated_config_set=<id> input_hash=<hash>
```

Generated config must be reproducible from typed config + DB state + deployment policy.

## DNS readiness

For each domain, compute record status:

```text
present
missing
mismatch
not_checked
unsupported
```

Record families:

- MX
- SPF
- DKIM
- DMARC
- DMARC reporting
- SRV/autoconfig/autodiscover
- TLSA when enabled
- MTA-STS when enabled
- TLS-RPT when enabled

DNS readiness output must identify exact expected value, observed value, and remediation text.

## TLS/ACME

ACME implementation:

- certificate backend plugin issues/renews certificates
- front service serves HTTP challenge path
- renewal writes audit event
- cert expiry and SAN coverage doctor checks run independently of renewal
- failure is visible in doctor output and does not silently fall back to self-signed certificates

## v1 plugin implementations

Required first plugins:

- webmail provider config plugin
- manual/export DNS plugin
- manual/Let's Encrypt cert plugin
- local filesystem backup storage plugin

Each plugin must implement v0 `PluginControl` plus its seam-specific service. All plugin health/version/capability calls must authenticate with service identity credentials.

Plugin failure behavior:

- DNS plugin failure prevents declaring DNS ready; it does not corrupt domain state
- cert plugin failure prevents certificate apply/renewal; it does not install invalid generated config
- backup plugin failure marks backup unavailable; it does not claim verified backup
- webmail plugin failure marks webmail unhealthy; it does not break daemon lookup paths

## Doctor

CLI/API:

```text
gotth-mailctl doctor --format text|json
GET /api/v1/doctor
```

Check categories:

- config
- DNS
- ports
- TLS/certs
- DKIM
- database
- Authentik reachability
- selected webmail reachability
- generated config
- daemon lookup health
- plugin health

Doctor result enum:

```text
ok
warn
fail
unknown
```

Doctor must distinguish config errors, external DNS/TLS state, daemon reachability, identity-provider issues, and plugin failures.

## Lookup debugger

CLI/API:

```text
gotth-mailctl debug lookup recipient <address>
gotth-mailctl debug lookup sender <address>
gotth-mailctl debug lookup dovecot <address>
gotth-mailctl debug lookup rspamd-domain <domain>
GET /api/v1/debug/lookup?...
```

Debugger output includes each decision step, source table/config, decision enum, and safe reason. It must not expose secrets.

## Mail flow trace

Trace phases:

1. recipient lookup
2. alias expansion
3. transport decision
4. spam/DKIM path
5. delivery mailbox
6. selected webmail visibility check when smoke test runs

Trace must be machine-readable and safe for UI display.

## Queue visibility

API:

```text
GET  /api/v1/queue/summary
GET  /api/v1/queue/deferred
POST /api/v1/queue/flush
POST /api/v1/queue/retry
```

Flush/retry are mutations and require authorization, confirmation where configured, and audit events.

## Smoke test

Smoke test creates a temporary test identity/mailbox or uses configured test fixtures. It proves:

- SMTP submission
- receive path
- alias delivery
- IMAP login
- DKIM signing
- delivered smoke mail visible through selected webmail provider

It must clean up created artifacts or report them explicitly.

## Snapshots

Snapshot captures:

- generated config set ID/hash
- image versions
- migration version
- plugin image/version
- deployment policy hash
- timestamp

Snapshot is not rollback unless paired with verified backup.

## Verification

Required tests:

- Postfix contract happy/failure paths
- Dovecot passdb/userdb/quota happy/failure paths, including Authentik-compatible encoded hash verification
- Rspamd DKIM/local-domain tests
- generated daemon config deterministic render/diff/apply/audit
- DNS readiness exact missing/mismatched record reporting
- ACME success or loud/actionable failure in reference deployment
- MTA-STS/TLS-RPT generation and doctor checks
- authenticated plugin health/version/capability checks for v1 plugins
- smoke test including webmail visibility
- mail delivery and daemon lookup tests with Authentik unavailable/isolated
- `git diff --check`
- `go test ./...`

## Exact-sender outbound forwarding (release 1.0)

Implement SignedForwardBuilder.Build(ctx, ForwardMessage) in internal/webmail.
ForwardMessage contains Identity, CapturedOriginal, MessageID and Date, all
owned by the admitted caller. The resolver must confirm the exact configured
address/fingerprint with no Sender override on each invocation. The builder
checks matching signed status and independently verifies matching exact-sender
status before returning bytes. All failures return nil bytes and empty status;
dependency errors become fixed safe diagnostics. No unsigned fallback.

Require a nonempty captured original; exact ASCII local address; canonical
40/64-hex fingerprint; explicit valid ASCII Message-ID; nonzero Date in years1..9999.
The admitted new-ID generator grammar is `<dot-atom-text@dot-atom-text>`
(RFC5322 sections3.6.4/3.2.3), at most255 bytes including brackets, ASCII atext
only, nonempty atoms on both sides; no leading/trailing/repeated dots, CFWS,
quoted/obsolete forms or domain literals. Reject before identity resolution.
This restriction is local to forwarding; existing shared parsers are unchanged.
Runtime private-key loading preserves binary bytes verbatim; only armor
detection/decoding uses trimmed text. A fixed synthetic whitespace-ending
packet must remain loadable singly and ambiguous when duplicated.
Do not parse original headers or choose identity/time/ID from them. The caller
must supply a NEW ID/time and authorize context; this API cannot prove their
provenance. From/Reply-To are the local identity, To is undisclosed-recipients:;,
Subject is Forwarded message, Sender/References/In-Reply-To/Cc/Bcc absent. Text
explains local forwarding responsibility without endorsing original authorship.
One attachment is original.eml, application/octet-stream, base64 at76 columns.

MaxForwardOriginalBytes = 50<<20 for the forwarding component only. Its checked
base64/framing oracle uses ceil(n/3)*4 plus ceil(n/57)*2 CRLF bytes, and the
documented maximum signed wrapper is 72,796,392 bytes. MaxForwardSignedBytes is
separate from the parser limit and remains below the existing verifier's
signed-entity ceiling. Check input before allocation/identity resolution,
message growth before encoding, and output before verification. The existing signer emits LF in its
detached ASCII armor: convert only lone LF to CRLF with one bounded copy, check
post-conversion size, then independently verify. Existing CRLF bytes remain
unchanged; noncanonical signed content would fail verification after conversion. These are component limits, not new
global mail limits or caller/concurrency admission. Buffers and crypto copies are
real, not streaming; budget and measure them.

MIME part reading keeps the existing 25MiB decoded limit and also treats the
encoded transfer stream as bounded input. Multipart traversal uses raw parts so
quoted-printable transfer decoding happens only inside this bounded reader. The
encoded reader may consume one sentinel byte beyond maxMIMEPartBytes; if it
does, the part is rejected even if base64 or quoted-printable decoding of the
prefix ended cleanly. This adds no full encoded buffer and does not change
MaxForwardOriginalBytes.

Tests trace FWD-1..4: decode byte-for-byte binary/LF/CRLF/QP/base64 original
fixtures; no inherited From/Reply-To/Date/Message-ID/Cc/thread headers; exact
attachment shape and seven-bit CRLF; existing real sign/verify, tamper denial;
real resolver lifecycle missing/revoked/expired/ambiguous key denials; malformed
metadata, cancellation and dependency failures with no output; limits at-1,at,+1
and independent arithmetic/size oracles. No external SMTP. Production capture
serialization, Bcc disclosure admission, actual keys and generator/forwarding
authority remain caller integration gates, not supplied by this helper.

Final transport integration must not create a second Postfix queue after policy
approval and then rely on stock smtp retry. The RED fixture at
/tank/development/linus/artifacts/gotth-mail-retrying-transport-first-slice-20261007T1335Z
shows queue A 4j0CN64kc7zpFdD admitted once, private 10027 creating queue B
4j0CN86T5CzpFdK, remote DATA first returning 451, policy revocation, and queue B
retrying to 250 with the same bytes/hash/Message-ID while the policy allow count
remains one. The fix is a thin delivery-agent gate: read the active DELIVER_REQUEST,
bind the immutable complete original final-envelope recipient set plus
authoritative provenance to the final queue, and ask the fail-closed broker to
evaluate that full set before any external DNS/connect. Outage/malformed/timeout tempfails. Forbiddance
durably records hold_required and tempfails; after request return, a privileged
reconciler holds and verifies the original queue, and release rechecks policy. On
allow, delegate the same request through Postfix deliver_pass to stock smtp, which
retains ORCPT/DSN, connection reuse and lost-DOT/4xx semantics. Do not reinject or
implement SMTP in the gate. Public SMTP remains 50MiB; private signed preparation
may produce 72,796,392 bytes. The prepared file is removed after unambiguous final
queue binding; that queue is sole post-bind body custodian. Initial maxproc=1 and
recipient_limit=1 remain until measured. Pin exact Alpine aports/APKBUILD/source,
patches, toolchain and license/SBOM/rebase evidence with the gate build.
