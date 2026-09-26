# v1.0.0-alpha.3 release and deployment

Date: 2026-09-26 CDT

## Accepted source and immutable tag

Danny accepted the outbound candidate after confirming inbox receipt. The
release tag points to that exact implementation rather than the later evidence
commits:

- annotated tag: `v1.0.0-alpha.3`;
- tag object: `8ce13201b75a066193b5551d21d912d15c11e140`;
- peeled implementation: `5dd9a6ec0ca196f311cc9c37d29db4f7a91af948`;
- source state: `5a6261eb961cf815dec7a9b8b202d5f81c585fc340e016c61d675cc3e2f01865`;
- Forgejo and GitHub expose the same tag object and peeled commit.

The `v1.0.0-alpha.1` and `v1.0.0-alpha.2` tags were not moved or rewritten.

## Reproducible artifacts

Two clean-tree production image builds produced the same role digests:

- control-plane: `sha256:7b3905fe1512af17625540e16b26bb1049d787804e5f9d27ccc2fcdd84606ab6`;
- front: `sha256:4e336b57f545051afe9b4976955ab1a65200b5a2a64fbfda0a1c743c27725f8c`;
- postfix: `sha256:dd2ee4e1ab92c022bac4d9fe06dea3e4754a5ef1c7bdfb01a7c3148f6906c035`;
- dovecot: `sha256:e9bfe576c2b6cbdea6e7035ce87bab296d70f5e4ec653cfab2c7b270690ec1c4`;
- rspamd: `sha256:ebd45f78a0c3c24c980346f6f7909d17d1a83d3582bf587732a426a3cfdea815`.

The release generator ran twice and emitted byte-identical configuration and
manifest outputs. The manifest declares database schema 18, matching migration
`0018_role_binding_authority.sql`.

- configuration archive: `dad355bde8346849d1f25af561c0852f16d0a41e559cbb6cb5728f509846ed02`;
- release manifest: `43215360f29e4c73c44d0ada8077be8a51147b87bfe164a3fa5d295b460b5e03`;
- image archive: `5a3ce8fb15d10831710351a1357790759cc8adb846820c8ae16d40b1f46465f0`;
- complete release archive: `66ff47de5ac03338a5626944df5c710f1eb471cbbcfc6c2ae8af71b9ff33911b`.

The webhook extension remains the immutable `v1.0.0-alpha.1` artifact with
digest `5cb6043ca200acfa67d4c6a85e0c1ba070c51dc550cacca7ce538021c8d9e83a`.

## Verification gates

- `go test ./...`: PASS;
- focused release, entrypoint, Postfix gate, and inspector tests: PASS;
- the same focused packages under the race detector: PASS;
- `go vet ./...`: PASS;
- production-build rejection contract, shell syntax, and `git diff --check`:
  PASS;
- both five-role build digest sets: exact match;
- both release-generator outputs: byte-identical.

One attempted second build initially hit the development host's missing Docker
bridge before producing an image. Re-running through the documented host
network path completed and matched every first-build digest. The development
root retained 240,095 free inodes after the builds, above the 100,000 stop
threshold; no historical recovery tree or shared container store was deleted.

## Deployment and rollback behavior

The final live release is
`/opt/gotth-mail-test/releases/v1.0.0-alpha.3-5dd9a6e`. The immediate rollback
is the accepted candidate
`/opt/gotth-mail-test/releases/dev-outbound-5dd9a6e-20260926T180305Z`; immutable
alpha.2 remains available at
`/opt/gotth-mail-test/releases/v1.0.0-alpha.2-0bdb230`.

Two fail-closed starts exposed deployment ownership drift before alpha.3 was
admitted:

1. the owner-only webmail runtime directory and registry file were `root:root`
   while the control plane runs as UID/GID 1000;
2. the release configuration archive correctly emitted mode `0440`, but a raw
   extraction left files `root:root`, unreadable by the UID/GID 1000 roles.

Each failed switch restored the accepted candidate. The runtime directory/file
now remain owner-only as `1000:1000` with modes `0700`/`0600`. Production
configuration remains non-world-readable as `root:1000`, directories `0750`,
files `0440`. No secret content was printed, changed, rotated, or committed.

## Live acceptance

- all six containers are healthy; the deployment service and Caddy are active;
- all five application containers run the exact alpha.3 image digests above;
- public ports 25, 143, 465, 587, and 993 are reachable;
- the public footer reports `Version: 1.0.0-alpha.3`;
- signed-out Chromium at 390 by 844 CSS pixels shows one sign-in state, zero
  visible mailbox toolbar controls, document width 390, document height 844,
  and zero page or horizontal scroll;
- authenticated submission negotiated TLS 1.3 with
  `TLS_AES_256_GCM_SHA384`;
- local queue ID `4hsc1y4Vxcz30Xd` delivered to Dovecot with DSN 2.0.0, was
  removed, and authenticated IMAPS found the exact Message-ID;
- external original queue ID `4hsc200fBnz30Xd` passed the guarded policy pipe
  and was replaced by `4hsc2012wLz30Y5`;
- Microsoft at `52.101.60.2` returned `250 2.6.0` with internal ID
  `102954661065872`; the replacement queue ID recorded `status=sent` and was
  removed;
- the final Postfix queue is empty.

The Microsoft response proves external SMTP acceptance of the alpha.3
verification message. It does not claim inbox placement. Danny's earlier inbox
confirmation applies to the exact accepted implementation, not this later
verification message.

## Remaining boundary

PTR remains generic Linode and DKIM is not published. Those are deliverability
hardening defects, not transport acceptance failures, and remain open after
this alpha release.
