# Notification binary-key repair — 2026-10-03

Status: ACCEPTED for this bounded repair after two fresh independent PASS reviews.
No feature/B5 completion, identity work, release, commit or deployment.

Existing requirements already demand unambiguous active identity/key admission.
No PRD/spec/interface/config-format expansion is required. The private notification
reader incorrectly trimmed binary data; the final signature whitespace octet of
a valid657B synthetic P256 entity was removed. Two copies1314B independently parse
two entities; trimmed1313B parses one, because pinned go-crypto ReadKeyRing skips
structurally unreadable entities. The configured notification constructor accepted
the ambiguous duplicate and signed/verified it while rejecting the valid single.

Only readNotificationKeyRing's binary reader argument changes from trimmed to
raw, with an adjacent bounded wrapper/delegated parser cost contract. Armored
text remains trimmed. Fingerprint, lifecycle, key protection and caller behavior
are otherwise unchanged; no broad strict-parser claim.

The deterministic public fixture remains at
internal/webmail/testdata/synthetic-whitespace.pgp (unchanged SHA256
fbc7918e856947a3ef5331f93669ade507692ac4ecff1b4b56a5d1f7cb4a9f35).
TestNewSignedEmailBackendPreservesBinaryKeyPackets in email_config_test.go
independently pins hash/counts/modes and exercises private loader plus configured
constructor/resolve/sign/verify. Binary and armor singles succeed; duplicates deny;
mode0644 denies. No SMTP submission, SQL, service or random key generation.

Actual promoted native RED exit1,0.025s; focused GREEN exit0,0.030s. Final immutable
snapshot a5f2ae5bc9cb29646f08892862bb13a0ea21e70f2b79401537fb3d839f44e37e:
existing development Go1.26.6/offline/GOMAXPROCS2/-p1; selected22 pure email cases
normal1.473s/race3.586s and notifyruntime vet all exit0. Changed reader100%, loader
90.3%, selected package31.7% coverage. The SQL recorder is explicitly excluded;
non-email, full-project and live suites are not claimed. Shared webmail crypto is
unchanged and exercised by real sign/verify paths; no reverse-dependency suite
expansion needed for this private notification helper.

No new key-buffer allocation: raw rather than trimmed byte view reaches parser.
Correctly parsing the second valid entity is required work, not a speedup. No
benchmark/performance campaign or changes to prior PG evidence.

Native logs, input manifests, before image and exact bounded diff are retained in
.artifacts/gotth-mail-beta-resume-20261003/notify-loader-fix/. Verification-only
RED packet remains unchanged in notify-loader-check/. Accepted F3 production
bytes/history and workflow state remain unchanged. Parent must obtain fresh
independent admission reviews and serialize subsequent identity work.

## Parent admission

Both independent reviews passed with no in-scope blocker. Parent read both,
rechecked the five-file seal and inspected the exact repair/regression. This
docs-only admission reuses unchanged native executable inputs; no rerun claimed.
The final review reports are retained in notify-loader-fix/review-one.md and
review-two.md under the evidence directory above.

Existing file protection means regular-file/permission checks, not a newly added
UID-ownership guarantee. The regression's smtpSubmitCalls=0 text describes the
absence of a Submit call; it is not an instrumented network counter. No broad
malformed-key guarantee or global B5/transport/deployment admission follows.
