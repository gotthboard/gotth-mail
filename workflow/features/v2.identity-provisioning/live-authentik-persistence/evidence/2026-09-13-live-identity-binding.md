# GOTTH Mail live identity binding — 2026-09-13

Status: local mechanism verified; live provider migration blocked.

Product line: `1.0.0-alpha`.

Historical workflow ID: `v2.identity-provisioning.live-authentik-persistence`.
The `v2` prefix is not a product version.

## Admitted component boundary

- `gotth-oidc` revision
  `1ae119e52f8efc3392fcc9fa716b1b27c9ffce6c` owns discovery,
  Authorization Code with S256 PKCE, protected attempt material, callback
  parsing, code exchange, and verified identity facts.
- `gotth-scim` revision
  `255629e27f7df301d263a116fb37fd315ff54693` owns SCIM protocol behavior,
  opaque resource IDs, transactions, ETags, search/PATCH/Bulk, tombstones, and
  write-only password delegation.
- GOTTH Mail owns PostgreSQL storage, one-time attempt consumption, browser
  binding, exact OIDC-to-SCIM identity composition, sessions, cookies, CSRF,
  mailbox/password/audit projection, Dovecot policy, and authorization.
- `gotth-authentik` is not imported because it has no owner-selected license or
  admitted release. `gotth-jobs` is not used on synchronous authority paths.

## Implemented mechanism

Migration `0006_oidc_scim_identity_binding` invalidates sessions whose old
identity provenance cannot be proved, records the exact issuer separately,
converts session ownership to a UUID foreign key, prevents two Authentik
subjects from sharing one mailbox, and normalizes the scoped role value.

The SQL callback transaction requires exactly one active SCIM User whose
`externalId` equals the verified OIDC subject and whose mailbox equals the
verified email. It commits the identity reference, session, and redacted
success audit together. Missing, disabled, ambiguous, email-mismatched,
reassigned, or conflicting identities fail closed. Forced audit failure rolls
back both identity and session authority.

SCIM disable/delete revokes dependent sessions inside the provisioning
transaction. Re-enabling the mailbox does not revive them. A fresh verified
login is required. Browser and API app-password operations derive the mailbox
from the bound session, require an independent CSRF proof for mutations, and
cannot cross mailboxes. The browser page is registered and linked only when a
durable session resolver is present; generated secrets are shown once and
verifiers are never rendered.

## Verification at reviewed head

Reviewed head before final evidence commit:
`846683cdef79b0a4c2ad667492c9486f2f40586d`.

Development-host PostgreSQL and repository gates:

- focused store/authn/authz/scimstore/API/HTTP UI/command tests: pass;
- `go test ./...`: pass;
- `go test -race ./...`: pass;
- `go vet ./...`: pass;
- all three commands build: pass;
- `go mod verify`: pass;
- `git diff --check`: pass.

Focused statement coverage:

- `internal/authn`: 85.5%;
- `internal/authz`: 93.1%;
- `internal/scimstore`: 41.6% package-wide;
- `internal/api`: 66.9% package-wide;
- `internal/httpui`: 61.8% package-wide;
- `internal/store`: 85.7%.

The lower package-wide API/SCIM/UI figures include unrelated historical
surfaces. The changed identity-binding success, rejection, rollback,
deprovision, re-enable, CSRF, same-mailbox, secret-once, and link-availability
paths are exercised. No false 100% claim is made.

Graphify `0.9.32` extracted the code-only tree to
`/home/linus/.cache/openclaw-graphify/gotth-mail-live-authentik/graphify-out/graph.json`:

- 1,764 nodes;
- 4,392 edges;
- SHA-256 `ef3829d84215ea063abce09f3f48864098aa48314b4eda228be57855d7ad312c`;
- three potentially sensitive fixtures skipped without inspection;
- six SQL files omitted because the optional SQL parser is absent; migration
  claims were verified directly from SQL and PostgreSQL tests instead.

Cold review found and repaired one userspace defect: an unconfigured runtime
advertised a link to an intentionally absent handler. Link and route exposure
now share the same durable-store condition and the UI uses the runtime clock.

## Live provider evidence and blocker

Public discovery probes on 2026-09-13 returned:

- desired `https://auth.dannyhunn.com/application/o/gotth-mail/`: HTTP 404;
- historical `https://auth.dannyhunn.com/application/o/gophermailforge/`:
  HTTP 200 with the historical issuer.

Therefore no live GOTTH Mail authorization-code, passkey, SCIM lifecycle, or
deprovisioning proof is claimed. The provider/application/redirect/profile
must be migrated to the GOTTH Mail namespace. That change requires either an
admitted licensed `gotth-authentik` release or an explicitly reviewed manual
desired-state operation. It also requires an interactive browser/passkey
acceptance and installed SCIM credentials supplied out of band.

No production deployment, release tag, GitHub mirror, or product-main merge
was performed by this feature.
