# Production artifact verification — 2026-09-20

## Exact candidate

- Mail source: `12dbe59973cba53e52d56437f21424b2ec53f3c8`;
- source-state SHA-256:
  `bfce82066676ecd4eaa38f879c29e8dc5cb610be3e8ccf41941ef0ca87a14366`;
- source epoch: `1789938083`;
- build identity: Go 1.26.6, linux/amd64;
- Stack consumer: `26a5e999b06394a4569f856d383b2a2b584a03c4`.

Forgejo and GitHub both resolve Mail's
`workflow/feature/release.1-0.production-artifacts` ref to the exact Mail
source commit. Both resolve Stack's
`workflow/feature/v3-mail-stack-runtime-adapters` ref to the exact Stack
consumer commit.

## Exact images

- control plane:
  `sha256:cb862c195f2b2a2077f33af843e84307c7476bd97f9947df6a041fd8d9bffab5`;
- front:
  `sha256:4fa4678b7132945c8aec6a2ff0866d5456c1f40e85007a6597d54a152d8097d1`;
- Postfix:
  `sha256:df672a4e9d1c5f0024b47a5b5ea00bb46b37e6662f225f0e1e746d6e478d31ce`;
- Dovecot:
  `sha256:542b1828f6158fed3124e7fafc2c8db94202d8873564b714d0308e67c88a3518`;
- Rspamd:
  `sha256:fe7b4f7a3db8ce9c453ad7585e1a752fbd109b5d36d7a35c2c236bd33d457fca`.

Two independent no-cache builds produced those same five IDs and identical
embedded binary SHA-256 values. The build uses the Docker exporter
`rewrite-timestamp=true`; `SOURCE_DATE_EPOCH` alone was correctly rejected as
insufficient because it does not rewrite filesystem-layer timestamps.

## Release artifacts

The assembler ran twice into separate directories and produced byte-identical
outputs:

- configuration USTAR SHA-256:
  `fa03341166fea00adef9e01d53816d982b103639f80ab9861f7b7f85d28fd331`;
- canonical manifest SHA-256:
  `d1f9886faa654a037aa2f0437ef52c982c91131a93e4969ad225fb9d0780aa08`.

The manifest binds all five repositories/digests, eight sorted configuration
members, schema 17, source/ref parity, toolchain, platform, and build epoch.
Its extension list is intentionally empty: this artifact proves the Stack
mechanism and is not represented as a publishable integrated alpha. The final
alpha must bind the independently released webhook extension.

## Runtime evidence

The fresh exact-source combined smoke passed real NGINX TLS/STARTTLS and auth,
Postfix policy/maps/queueing, Rspamd milter and SQLite Bayes state, Dovecot
LMTP delivery, Maildir persistence, and authenticated IMAPS readback under the
fixed users, capabilities, read-only roots, tmpfs, and file-secret contract.

Stack then consumed the exact canonical manifest/archive and exact Rspamd
digest. Its root-only race test passed fresh install, secret-revision
replacement, adapter close/reopen, candidate verification, reverse rollback,
and durable SQLite Bayes retention in 50.70 seconds.

## Repository gates

- `go test -count=1 ./...` — passed;
- `go test -race -count=1 ./...` — passed on the final implementation commit;
- `go vet ./...` — passed;
- shell syntax and production build-contract checks — passed;
- hostile release configuration/no-replace tests — passed;
- `git diff --check` — passed;
- two fresh cold reviews — clean.

The earlier apparent smoke/Stack proof reused an image labeled with nonexistent
commit `acd1100207f018623b9f2a7156ffed8d53c3222a`. It is explicitly invalid and
is not part of this admission.

## Limits

No production image, tag, or release has been published. No credential, DNS
record, public listener, mailbox, live Authentik tenant, or deployment was
changed. The webhook release, identity-library tags, integrated alpha,
backup/restore, live deployment, beta hardening, and owner acceptance remain
separate mandatory work.
