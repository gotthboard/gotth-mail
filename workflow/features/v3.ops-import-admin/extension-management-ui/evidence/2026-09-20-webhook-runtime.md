# Webhook extension runtime evidence — 2026-09-20

## Candidate identity

- GOTTH Mail supervisor: `9ae6270`
- repeatable Mailu smoke repair: `4c3cf6b`
- independent extension repository: `gotthboard/gotth-extension-webhook`
- extension candidate: `95af997`
- extension ID: `gotth.mail.notification.webhook`
- interface: `gotth.mail.interface.notification`
- candidate version: `1.0.0-alpha.1`
- canonical manifest SHA-256:
  `0f515328c232f9c0db4d1e95be4877b7819815e5ade4cd6936ea823115d5c79e`

## Boundary proved

The production adapter admits only the exact webhook identity, interface,
capabilities, metadata keys, and `webhook.hmac-key` secret slot. It verifies a
digest-named artifact and pinned manifest, projects configuration, binding,
service token, and HMAC key through owner-only non-symlink files, starts the
child in its own process group with parent-death signaling, authenticates Unix
gRPC, validates the full foundation handshake and health response, and admits
alert routing only after validation.

The real cross-process test builds the independent extension and proves start,
probe, route admission, bounded outbound failure, refusal to stop while routed,
route revocation, confirmed process termination, and runtime-secret removal.
Static notification-plugin configuration conflicts fail startup. No Telegram
extension or prompt route is introduced.

## Verification

Development host: `10.0.0.97`.

The following gates passed from clean development worktrees:

```text
gotth-extension-webhook: make verify
gotth-extension-webhook: reproducible Linux/amd64 artifact build
gotth-mail: git diff --check
gotth-mail: go test -p=2 ./...
gotth-mail: go test -race -p=2 ./...
gotth-mail: go vet ./...
gotth-mail: go build ./...
containerized-mailu-import-smoke.sh (two consecutive runs)
containerized-outbound-policy-smoke.sh
containerized-notification-plugin-smoke.sh
containerized-webmail-imap-smoke.sh
containerized-webmail-smtp-smoke.sh
containerized-webmail-runtime-smoke.sh
containerized-webmail-ui-smoke.sh
reference-runtime-smoke.sh
```

The initial repeated Mailu smoke collided with the fixed Compose project left
by an overlapping run and failed on duplicate `user@example.test`. The harness
now uses a per-process default project name and performs a preflight cleanup.
Two consecutive post-repair runs passed. This was a verification-harness
repeatability defect, not a hidden product waiver.

## Remaining release boundary

Repository implementation and integration are complete. Production
installation remains closed until the public GitHub repository exists and the
one-way mirror, immutable tag/artifact, and Forgejo/GitHub release parity are
proved. Live rollback and delivery-ambiguity acceptance still require the
authorized deployment target.
