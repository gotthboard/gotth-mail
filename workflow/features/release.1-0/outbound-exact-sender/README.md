# Outbound exact sender

Canonical state is workflow.toml; IN PROGRESS, not beta completion.

Owner reprioritized signing on2026-10-03. The UI feature remains blocked on
remaining acceptance, with its accepted dirty work frozen in the separate
beta-acceptance worktree. No UI source is copied into this branch.

## Ordered units

1. F3: FWD-1..4 contracts and SignedForwardBuilder.Build with existing
   lifecycle/sign/verify interfaces. One atomic production unit: returning an
   unsigned intermediate would violate its public contract. RED before code,
   GREEN before next unit. Real crypto and opaque-byte equality oracles.
2. Authoritative forwarding identity/context and initial expansion provenance;
   bind the immutable complete original final-envelope recipient set to the final
   queue. Non-null forwards use the configured local identity as envelope sender
   and local DSN destination; remote authors are never envelope authority and
   null-sender triggers remain null/bounce-suppressed.
3. Final delivery uses a thin DELIVER_REQUEST gate: fail-closed broker evaluation
   of the full bound set before external DNS/connect, then deliver_pass delegation
   to stock smtp on allow. No reinjection, custom SMTP or unsigned fallback.
   Full-size resource/capture proof and independent reviews remain required.

Unit1 is preparation for the actual Gate.Deliver caller, not a substitute.
No configured production identity/key is selected. No external SMTP in tests.
Budget:90min product work including checks,10min handoff reserve; checkpoint
after45min, handoff by11:30UTC2026-10-03. No checker installed: standard TOML
parse/ID/dependency/active checks are limited evidence, not workflow-check PASS.

Trace: v1 PRD/architecture/spec Exact-sender outbound forwarding sections →
internal/webmail/forward_mime.go → forward_mime_test.go; existing openpgp and
runtime tests remain regression gates. Final all-outbound integration pending.

## F3 component checkpoint — 2026-10-03

SignedForwardBuilder.Build and its tests are implemented; independent review
and actual caller integration remain pending. Final development Go1.26.6 normal,
race and vet passed over snapshot
aaa0a61b2d0f182443f6e92b8cac91b137270ce083860283fdfdcfe2d5c103a2.
Seven SQL tests were intentionally excluded and three unconfigured live tests
skipped. Helper coverage95.7%; remaining statements are standard multipart
error returns over an owned non-failing bytes.Buffer, not untested authority.
Boundary original19,156,674B, signed output27,525,120B; actual parser recovers
the original at the boundary. Existing50MiB capability remains an integration
gate. Costs include roughly160.52MB allocation for one boundary operation; no
streaming, full-scale performance or all-outbound conformance is claimed.

## Revision2 review repair — 2026-10-03

Both original reviews rejected malformed generated IDs; review-one additionally
required the binary ambiguity regression. IDs now use the documented local
ASCII dot-atom grammar before resolver access. A fixed public synthetic binary
fixture reproduces trim-induced ambiguity admission and valid-single rejection.
The runtime loader now preserves raw binary while keeping armor behavior.
Focused native RED→GREEN and source-matched webmail normal/race, notify email
family normal/race and both-package vet pass; SQL/live exclusions apply.
Executable snapshot1ba147d579207f1eb051b4c85d1beaaafd7c2c8e5501b08ddbee1b51c78b96af.
Validator100% coverage; loader83.3%, Build95.7%. Conservative retained accounting
exceeds512MiB planning target (~516MiB counting all preexisting shared caches),
not a measured peak or physical-limit violation; see revision2 evidence.
Feature remains in_progress, B5 open; fresh independent review is required.

## Scoped F3 admission — 2026-10-03

Two fresh independent revision2 PASS reviews and parent admission supersede
the earlier pending-review wording. [Component evidence](evidence/2026-10-03-forwarding-component.md)
records the tested source, exclusions and remaining boundaries. This closes the
bounded F3 component only. Implementation work now yields to the owner-prioritized
identity feature; final transport/provenance/retry/full-size and notification-loader
follow-up remain open. No whole-feature completion or deployment.

## Notification loader repair checkpoint — 2026-10-03

The separate binary-loader concern was reproduced through configured notification
crypto and minimally repaired. [Repair evidence](evidence/2026-10-03-notification-binary-loader.md)
records promoted native RED/GREEN, selected email normal/race/vet and exclusions.
Two fresh independent reviews passed; parent accepted this bounded repair.
It does not rewrite scoped F3 admission or close B5/transport/provenance/retry/
full-size gates.

## U547 + S531 component integration plan — 2026-10-04

This detached merge-staging exception composes the accepted UI snapshot and
only the accepted signing/notification 15-file delta. Earlier branch-local
statements above remain historical; this staging tree now contains accepted UI.
Canonical FWD-1..4 PRD → architecture → implementation spec are imported before
this plan and before code. The outbound child is the sole active integration
unit; UI remains incomplete/non-active and beta remains planned.

Acceptance: exact accepted component bytes/modes and public fixture; unchanged
U code/templates/assets/authority tests; complete changelog history; structural
TOML state/dependency/path checks (no available workflow-check executable); source-bound development normal/race signed-forward and
notification-loader families, focused permissions HTTP/native PostgreSQL checks,
and integrated command build/vet. Map binary dependencies before browser reuse;
retain any exact-final-artifact browser gap rather than claiming old proof.

Evidence is staged outside product source under
.artifacts/gotth-mail-beta-resume-20261003/component-integration-signing/ in the
parent workspace. Freeze the full candidate, report exclusions/resources and
STOP for two sequential fresh independent parent reviews before admission.
No artificial RED: this imports accepted tested components without new behavior.
No identity import, new production caller, SMTP/custody/schema redesign, B5,
full-size transport, beta entry, commit, publication or deployment is authorized.

## Scoped component integration admission — 2026-10-04

Parent accepted this U547 plus S15 composition after two sequential fresh,
independent corrected-candidate PASS reviews. No mandatory residual finding
remained. Accepted UI and signing originals stay unchanged; this is a detached
merge-staging candidate, not a promoted branch or completed outbound feature.

New source-bound checks passed:41 normal,41 race and3 PostgreSQL17 selected
cases, scoped vet and command builds. One fresh command-test build supported
two successful unchanged permissions browser runs. The corrective second run
observed the actual PostgreSQL SQL server identity and hard limits, not merely
its version probe. Earlier missing observations and failed dispatch remain
historical limitations; no retrospective receipt or new full-suite claim.

The parent closeout changes only this ordinary Markdown record and CHANGELOG;
all executable inputs remain unchanged. Applicable checks are reused, not rerun;
the final documentary state was not compiled. Missing workflow tooling is a
limitation, not a checker PASS; no workflow DONE transition occurred.
Identity integration, the production forwarding caller/final SMTP signing,
full-size/retry/custody behavior, full-suite/performance/live/beta gates remain
open. No publication, deployment or external authority is admitted.

## Focused outbound provenance recovery — 2026-10-04

Active selector temporarily moves here for one narrowed unit: prove and repair
queue-time equal original/final provenance without reopening signing, SMTP,
schema, retry, crypto or beta scope. The unit is limited to contracts, focused
regression tests, one minimal `resolveExpansionDeliveries` guard, and source-
bound evidence. Accepted UI/signing/identity artifacts remain preserved; this is
not feature DONE, release admission, deployment, or publication. Full package,
race, caller, static and independent-review gates remain required if not closed
inside the recovery window.
## MIME encoded-limit repair plan — 2026-10-04

Parent authorized one focused production unit on the accepted601 composition:
prove and repair encoded MIME-part overrun handling in internal/webmail/mime.go.
The unit is limited to preserving the 25MiB decoded cap while independently
rejecting base64/quoted-printable encoded streams that cross the encoded cap;
MaxForwardOriginalBytes, 50MiB/full-size forwarding, identity, SMTP and native
retry remain open. RED must come from unchanged production before the minimal
reader repair; no workflow selector or feature completion changes.

## MIME multipart raw-part repair — 2026-10-05

Cold review found Go multipart.NextPart hides quoted-printable transfer headers
and predecodes child bodies before readMIMEPart can enforce the encoded-octet
cap. This bounded repair switches multipart traversal to raw parts so the same
existing bounded decoder path handles top-level and multipart bodies. It does
not change size constants, workflow state, forwarding transport, identity or
beta scope.

## Full-size SignedForwardBuilder component — 2026-10-05

This unit is limited to the in-memory builder accepting a 50MiB captured
original and producing a bounded signed wrapper. It does not wire Gate callers,
Postfix limits, retry, identity authority, custody, concurrency or beta. The
hostile-display MIME parser remains capped independently; full-size tests use a
forwarding-specific opaque recovery oracle.

## Retrying transport RED — 2026-10-07

A two-container internal-bridge fixture reproduced the current-policy retry bypass in the unchanged private-10027/content-filter topology. Evidence root: /tank/development/linus/artifacts/gotth-mail-retrying-transport-first-slice-20261007T1335Z. Queue A 4j0CN64kc7zpFdD was admitted once by gotth_policy, private 10027 created queue B 4j0CN86T5CzpFdK, remote DATA first returned 451, policy was revoked, postqueue flush retried queue B, and the remote accepted 250 with identical bytes/hash and Message-ID while the policy allow count stayed one before and after. Distinct internal containers/IPs and cleanup are recorded.

This closes only the RED/design-freeze slice. The feature remains in_progress. No production code/config/migration/Postfix patch/ref/commit/deploy is admitted. Next implementation keeps the final queue as sole body custodian, binds its immutable complete original final-envelope recipient/provenance set, and inserts a thin delivery-agent gate. Every qmgr request asks the fail-closed broker to evaluate that full bound set before external DNS/connect, then delegates allowed requests through Postfix deliver_pass to stock smtp. Forbidden hold_required denies later batches until a privileged verified hold; release rechecks. Non-null forwarding uses the configured local envelope/DSN identity, remote authors are never envelope authority, and null triggers remain null. The gate must not reinject or implement SMTP.

## Final queue artifact binding correction checkpoint — 2026-10-07 13:50 UTC

Parent rejected the first green unit for duplicate queue authority. The corrected unit removes internal/finalqueue and implements artifact intent/binding in internal/outboundpolicy. Prepared artifact recipients/sources are prequeue intent; final_queue_bindings references existing outbound_queue_messages and QueueStore.Load remains post-bind delivery authority. Bind compares arrival fingerprint, canonical sender/null mapping, recipient membership digest and source membership digest before commit; lookup revalidates artifact rows/digests/state plus the observed QueueStore record. Caller-supplied domains and digest authority are not accepted; provenance digest is derived from canonical immutable fields and source revisions. No body/secrets/spool/caller/broker/socket/C gate/Postfix config/build/deploy/DNS/ref/commit/PR/push is included. Parent review remains the next gate.

## Final queue artifact binding review-one correction — 2026-10-07 14:45 UTC

Cold review0647c4b7 rejected the previous candidate for split authority snapshots, timestamp precision drift, incomplete ordinal/state checks, duplicated Message-ID grammar, false complexity comments and missing cleanup receipt. The corrected unit keeps binding in outboundpolicy, loads artifact/binding/observed QueueStore rows in one SQL transaction, locks observed queue parents, canonicalizes signed/prepared/updated/expires/bound times to UTC PostgreSQL microsecond precision before digest/persist/compare, validates exact child ordinals and lifecycle timestamps, shares the generated Message-ID grammar with webmail, removes the redundant artifact index, preserves COPY rollback evidence and adds focused native concurrency/timestamp/tamper coverage. This remains metadata/binding only; no caller, spool, broker, C gate, Postfix config, build, deploy, DNS, ref, commit, PR or push. Parent review remains the next gate.
