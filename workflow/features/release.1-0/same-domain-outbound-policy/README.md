# Per-domain same-domain-only outbound policy

## State

Done. The implementation, hostile-path tests, reference-stack proof, repository
gates, and two independent final clean reviews are recorded in this feature's
evidence. It remains a completed dependency of `release.1-0.alpha-integration`.

## Objective

Allow an administrator to set one hosted domain to `same_domain_only`, causing
every mailbox and system sender bound to that domain to send only to recipients
in the exact same canonical domain. Governing domains also include admitted
envelope-sender and expansion-source domains, closing delegated send-as and
forwarding bypasses. Inbound mailbox delivery remains independent.

## Required surface

- durable enum and policy revision with `unrestricted` compatibility default;
- digest- and revision-bound preview/confirm activation and explicit rollback;
- authenticated SMTP `RCPT TO` and final Postfix enforcement;
- atomic webmail/API recipient-set enforcement;
- alias, forward, list, BCC, and catch-all post-expansion enforcement;
- delegated cross-domain send-as, inbound forwarding, and chained-expansion
  enforcement from authoritative local object identities;
- notification, autoresponder, DSN, and bounce enforcement without loops;
- retry, flush, replay, restored-queue, and final-handoff re-evaluation;
- visible, non-destructive whole-message Postfix policy hold when any remaining
  queued recipient is forbidden, with idempotent reconciliation;
- generated configuration, diagnostics, audit, backup, restore, and rollback;
- hostile-path tests named in `workflow.toml` and the implementation spec.

## Non-goals

- no change to inbound mailbox acceptance; outbound forwarding still crosses
  the policy boundary;
- no implicit trust for subdomains or other locally hosted domains;
- no header-based policy, internal-sender bypass, or permissive failure mode;
- no automatic hold release when the policy returns to `unrestricted`.

## Admission boundary

The feature is admitted as complete on the repository line. This is not a live
deployment claim: no production domain policy, queue, credential, DNS record,
tag, release, or external service was changed.
