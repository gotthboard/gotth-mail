# Main history reconciliation — 2026-09-20

## Decision

The alpha integration branch was created from repository-verified candidate
`ae734ae` and merged canonical `main` at
`fb1fcb893bf47aa00014c1a55b156603d463eb9a` with Git's `ours` merge strategy.
The merge commit is `cc80b9d`.

This is ancestry reconciliation, not content replacement. Canonical `main`
contains three commits made independently on the protected release line:

- `a53b44e` — OpenPGP exact-sender drafts;
- `e3e660a` — GOTTH Mail rename;
- `fb1fcb8` — rename admission evidence.

The development line contains their corresponding work at `e39a402`,
`2eb0d62` through `26b2059`, and `1b65290`, followed by all identity, webmail,
notification, outbound-policy, extension-foundation, administrator, and
supervisor implementation. Range review showed that replaying main would
replace later implementation and evidence with stale intermediate content.

## Mechanical proof

```text
first parent:  ae734ae64e990b0b6336818d29c353b20865fd5d
second parent: fb1fcb893bf47aa00014c1a55b156603d463eb9a
merge:         cc80b9dd924032243ca5544910b1c7ba6101482b
git diff cc80b9d^1 cc80b9d: empty
```

The content-preserving merge therefore records both histories without changing
the already verified candidate tree. No tag, release, deployment, credential,
DNS record, or runtime state changed.

## Remaining gate

This starts alpha integration; it does not complete it. Publication remains
blocked on public extension artifact parity, live identity acceptance and
library tags, deployed lifecycle/recovery proof, and an exact reproducible
alpha artifact.
