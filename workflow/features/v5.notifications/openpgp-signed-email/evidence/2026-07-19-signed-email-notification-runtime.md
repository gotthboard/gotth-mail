# v5 signed-email standalone plugin-adapter evidence

Date/time: 2026-07-19 06:55 CDT

Feature: `v5.notifications.openpgp-signed-email`

Branch: `workflow/feature/v5.notifications.openpgp-signed-email`

Base: `d432e5b` (`Recover local implementation checkpoint`)

Commit: current local commit; hash assigned by Git after commit

## Scope

Implement one explicit standalone plugin adapter for outbound alert email with no unsigned fallback:

- a distinct opt-in `signed-email-notification-sink` plugin;
- bounded alert sanitization before MIME construction, including fail-closed secret-bearing identifiers, full pre-truncation detail-key checks, and typed evidence filtering;
- exact configured system sender/key lifecycle revalidation for each delivery;
- RFC 2047/quoted-printable seven-bit MIME with stable alert-derived Message-ID;
- real OpenPGP/MIME signing with one canonical headerless detached-signature armor block, exactly one SHA-256 packet, exact packet/micalg agreement, and byte-exact cryptographic verification of the raw signed entity;
- trusted-local-relay SMTP submission only after verification;
- typed bounded exact-sender evidence carried over gRPC and persisted in SQL.

The default Telegram first-mechanism registry remains unchanged. Signed email does not inherit prompt or mutation authority.

## Cross-cut boundaries

This slice uses `source_path = "."` because its reviewable mechanism crosses these explicit boundaries: `cmd/gmf-plugin` process composition, notification protobuf/generated bindings, plugin gRPC mapping, notification sanitization and SQL recorder, `internal/notifyruntime`, shared webmail OpenPGP/MIME and SMTP code, store schema migration, opt-in Compose registration, contract/container tests, and the matching docs/workflow evidence. It does not grant the feature ownership of unrelated repository paths.

## Runtime configuration

The signed-email plugin requires these values together:

- `GMF_NOTIFICATION_EMAIL_FROM`
- `GMF_NOTIFICATION_EMAIL_TO`
- `GMF_NOTIFICATION_EMAIL_SIGNING_FINGERPRINT`
- `GMF_NOTIFICATION_EMAIL_PRIVATE_KEY_FILE`
- `GMF_NOTIFICATION_EMAIL_SMTP_ADDR`

Startup rejects partial configuration. Startup and each delivery reject private-key files that are empty, malformed, oversized, non-regular, group/world accessible, encrypted, public-only, ambiguous, mismatched, revoked, expired, disabled, replaced by an unconfigured key, or lack usable signing material. SMTP targets must be loopback/private IPs or validated single-label local service names because the adapter intentionally has no remote TLS/authentication policy. Literal public IPs and dotted hostnames are rejected; a single-label name delegates trust to the deployment's local/container resolver. Envelope addresses must be ASCII because SMTPUTF8 is not required or assumed. No key material or SMTP credential is stored in the repository.

## Admission and failure behavior

The release order is:

```text
sanitize -> reload and resolve lifecycle/binding -> build seven-bit stable-ID MIME
  -> sign -> verify the exact raw entity, exact sender, and authoritative headers
  -> trusted local SMTP -> typed bounded delivery result/evidence
```

Verification requires exactly one canonical headerless detached-signature armor block containing exactly one SHA-256 packet as advertised by `micalg=pgp-sha256`, binds that signature to the exact transmitted first MIME entity, and separately checks From, optional Sender/Reply-To, Message-ID, Date, Subject digest, and signing fingerprint. Garbage prefix/suffix, armor headers, noncanonical/no-checksum encodings, multiple packets, duplicate outer authoritative headers, duplicate signed security headers, unsigned extra-header injection, structurally plausible forgeries, and body/header mutation never reach SMTP. Key types whose maintained signing path cannot emit SHA-256 fail at configuration and remain permanent failures after per-delivery reload. Resolver, signer, verifier, and SMTP error text is not returned through the plugin delivery result; arbitrary sink reasons are reduced to the machine-readable reason contract. Sink-supplied gRPC descriptions and details are discarded for both alert and prompt RPCs and rebuilt from fixed server-owned status text, including the intentional prompt-only `Unimplemented` result.

JSON-quoted, multiword, Unicode-whitespace, bearer, and armored-private-key secret markers redact their entire alert field before MIME construction. IDs, classes, correlation IDs, and resource types carrying secret markers are rejected before bounding. Detail keys are checked in their complete normalized form before truncation, and bounded-key collisions cannot restore a value already marked secret. Delivery evidence is admitted field by field against its typed grammar and secret checks before it can cross the in-memory, SQL, or gRPC boundary; invalid fields are dropped rather than persisted or echoed.

Successful evidence contains transport, Message-ID, generation time, From/Sender, signing fingerprint, sender identity ID/class, policy version, lifecycle reference, `valid_exact_sender`, and workflow. A fresh-schema integration test composes the signed backend with the SQL recorder and reloads the real delivery evidence. The old-schema upgrade test separately writes and reloads representative structured evidence through the upgraded recorder; it does not execute the signed backend.

The SQL upgrade path preserves the immutable `d432e5b` baseline migration definitions and validates the complete `schema_migrations` ledger before applying a missing known upgrade. Missing baseline rows, dirty or checksum-mismatched known rows, and unknown/future versions fail before upgrade DDL. The canonical `0002_notification_delivery_evidence` file, runtime SQL, identifier, and checksum are parity-checked; a pre-existing wrong-shaped evidence column fails closed. Migration and isolated-restore transactions set `search_path` to `public, pg_catalog`, and restore readback is schema-qualified, so a hostile caller search path cannot redirect schema creation, data insertion, or verification into a shadow schema. Empty-target restore admission still rejects any existing user relation in `public` before DDL.

SMTP outcomes distinguish permanent rejection, retryable pre-acceptance failure, and ambiguous DATA acceptance. Ambiguous acceptance is not blindly retried, and a failed QUIT after successful DATA acceptance does not create a duplicate-delivery retry.

## Verification

- repeated focused/adversarial package tests for `cmd/gmf-plugin`, `internal/notification`, `internal/plugin`, `internal/notifyruntime`, `internal/ops`, `internal/store`, and `internal/webmail`, including canonical armor/single-packet admission, unsupported-key permanent classification, raw-entity/header mutation, lifecycle transitions, pre-bound secret rejection, typed evidence filtering, fixed-text alert/prompt gRPC failures, complete migration lineage, hostile search paths, wrong schema shape, and isolated-restore rejection;
- `go test -race -count=1 ./cmd/gmf-plugin ./internal/api ./internal/notification ./internal/plugin ./internal/notifyruntime ./internal/ops ./internal/store ./internal/webmail`;
- `go test -count=1 ./...`;
- `go vet ./...`;
- `sh -n` for every repository shell script;
- `git diff --check -- .`;
- pinned protobuf regeneration into a temporary directory, byte-identical to the checked-in Go bindings;
- `sudo -n docker compose -f compose/reference/docker-compose.yml --profile signed-email-notification config --services`, including `signed-email-notification-plugin`;
- old-schema PostgreSQL migration, idempotent rerun, baseline dirty/checksum rejection, wrong-column-shape rejection, fresh/upgraded ledger equivalence, file/runtime SQL parity, and empty-only isolated-restore regressions;
- notification smoke project `gmf-notification-plugin-smoke-final-20260719-6`, terminal exit `0`;
- explicit marker: `containerized notification plugin gRPC/backend smoke passed`;
- explicit in-container pass for `TestSignedEmailNotificationSinkGRPCDeliversCryptographicallyVerifiedSMTPAndRejectsPrompt`;
- webmail SMTP/OpenPGP smoke project `gmf-webmail-smtp-smoke-final-20260719-3`, terminal exit `0`;
- explicit marker: `containerized webmail SMTP smoke passed`;
- no residual containers, networks, or volumes for either final project after cleanup.

The integration builds and starts the real standalone `gmf-plugin` process, traverses authenticated TCP gRPC, the real per-delivery key loader/resolver, real OpenPGP signer and raw-entity verifier, real `NetSMTPSubmitter`, and a local capture SMTP server advertising neither 8BITMIME nor SMTPUTF8. Its non-ASCII alert is transported as seven-bit MIME, the captured post-transport entity verifies cryptographically as the exact configured sender, and the gRPC evidence Message-ID matches the wire message. It sends no external email and makes no Telegram API call. It does not prove control-plane dispatcher selection or recorder composition.

The opt-in `signed-email-notification-plugin` Compose service is contract/config validated but is not the live Compose service started by the notification smoke. That smoke starts the existing Telegram plugin service, then runs the signed-email real child-process gRPC/SMTP integration inside the containerized test-runner.

## Explicit coverage gaps

- `SignedEmailBackend.SendAlert` retains one defensive MIME-builder error after its inputs have already been sanitized and validated; the operational admission and failure branches are directly tested.
- Key-loader gaps are defensive parser-impossible nil/dummy states and injected filesystem stat/read failures. Missing, revoked, expired, ambiguous, mismatched, disabled, encrypted, public-only, malformed, empty, oversized, permission, and key-replacement transitions are covered.
- Keys whose maintained go-crypto signing path cannot emit SHA-256 fail closed; this adapter does not silently relabel SHA-384/SHA-512 signatures.
- SMTP 451/550 and pre-acceptance DATA-drop outcomes have direct classifier coverage; only the accepted-DATA/failed-QUIT boundary is exercised through a real socket server. Network-injected 451/550/DATA-drop integration remains unproved.
- Context cancellation after SMTP dial does not proactively close the connection; completion is bounded by the configured/effective socket deadline rather than immediate cancellation.
- The canonical feature remains `in_progress`: the v5 root's v3 prerequisite, declared Telegram/app-password dependencies, control-plane routing/selection and recorder composition, per-user/role/delegation identity selection, message-context authorization, recorded public-key discovery, complete rotation/deletion/recovery policy, production encrypted-key unlock/HSM/KMS custody, and rotation automation remain work. The implemented standalone system-identity adapter has no unsigned fallback.
- Live Telegram delivery remains a separate external confirmation boundary and is not claimed here.

## Recovery note

The volatile prior worktree was lost before this continuation. The pre-slice repository was reconstructed from the exact Docker build image checkpoint and committed locally as `d432e5b` (`Recover local implementation checkpoint`); the recovered signed-email delta was then moved onto this dedicated v5 feature branch and the canonical worktree root was changed from volatile `/tmp` storage to `/tank/development/linus/gophermailforge-worktrees`. Nothing was pushed.
