# GopherMailForge PRD

## 1. Product summary

GopherMailForge is a Go-based mail-server control plane and deployment system that uses Mailu as the reference architecture and executable behavioral specification, while deliberately avoiding a line-for-line rewrite of Mailu's Python admin application.

The product should run a complete self-hosted mail stack using proven mail daemons and container boundaries:

- SMTP ingress/proxy: nginx-style front service
- SMTP delivery/submission: Postfix
- IMAP/POP3/auth/quota: Dovecot
- spam/DKIM/filtering: Rspamd
- webmail: required webmail service selected by deployment policy
- identity provider: required Authentik service/profile, never embedded in the mail server
- control plane: GopherMailForge, written in Go
- persistence: explicit relational schema and migrations
- generated configuration: typed, reproducible, inspectable daemon config

Mailu is the baseline for concepts, service boundaries, deployment assumptions, and admin/domain/mailbox semantics. GopherMailForge is not a fork of Mailu and must not inherit Mailu's accidental Python/Flask/SQLAlchemy/API cruft.

## 2. Problem statement

Mailu proves the architecture works: split stable mail daemons into containers, keep user/domain/config state in an admin control plane, and expose internal lookup endpoints consumed by Postfix, Dovecot, Rspamd, fetchmail, and frontend services.

The weak part is not the mail architecture. The weak part is the historical control plane shape:

- dynamic Python model behavior obscures contracts
- environment/config handling is broad and stringly typed
- internal daemon APIs are implicit route behavior instead of a first-class contract
- migrations and schema ownership are not clean enough for a new implementation
- validation bugs can hide behind permissive coercion
- background jobs and operational tasks are not a clean product surface
- API behavior reflects accumulated history rather than a deliberately versioned interface

GopherMailForge exists to keep the proven Mailu deployment model while replacing the control plane with a smaller, typed, explicit Go system.

## 3. Goals

### 3.1 Reference Mailu, do not clone it

Use Mailu as the reference for:

- service decomposition
- domain/user/alias/relay/fetch/token concepts
- container deployment assumptions
- daemon-facing internal endpoints
- generated DNS guidance
- DKIM key lifecycle
- REST and SCIM provisioning expectations
- operational flows around setup, initial admin creation, and Compose deployment

Do not preserve Mailu behavior merely because it exists. Preserve behavior only when it is required for mail-stack compatibility, operator expectation, or documented API compatibility.

### 3.2 Build a serious Go control plane

The control plane must provide:

- typed configuration model
- explicit database schema and migrations
- deterministic config generation
- strict request validation
- observable internal daemon endpoints
- admin API with stable versioning
- SCIM 2.0 user provisioning subset
- clear background job model
- operational commands for bootstrap, config validation, and diagnostics

### 3.3 Keep the mail daemons boring

GopherMailForge should not reimplement SMTP, IMAP, spam filtering, DKIM signing, or webmail. That would be architecture cosplay. Use mature daemons and generate their configuration correctly.

### 3.4 Make local self-hosting understandable

A competent operator should be able to inspect:

- what containers run
- which ports are exposed
- where persistent data lives
- what config was generated
- which database migrations ran
- which domains/users/aliases exist
- why a daemon lookup returned a given result

Hidden magic is a defect.

## 4. Non-goals

GopherMailForge will not initially:

- replace Postfix, Dovecot, Rspamd, Redis, or webmail implementations
- implement a Kubernetes-first product
- embed Authentik or any other identity provider inside the GopherMailForge binary/control plane
- let Authentik availability break mail delivery, daemon lookups, bootstrap, or emergency recovery
- support every historical Mailu plugin/integration on day one
- preserve every Mailu REST quirk
- provide multi-node clustering
- provide hosted SaaS control-plane features
- become a generic mail framework
- support arbitrary daemon topology before the Compose reference path works
- import Mailu's Python code or templates mechanically

If there is one deployment target at first, it is Docker/Compose. Generalizing before that works is fake abstraction.

## 5. Reference system: Mailu inventory

This PRD is based on inspection of Mailu's current structure in the local reference checkout.

### 5.1 Service architecture to keep

Mailu's service split is the baseline:

- `front`: nginx frontend/proxy exposing mail and web ports
- `admin`: control plane and admin web/API application
- `imap`: Dovecot for mailbox access and auth lookups
- `smtp`: Postfix for SMTP delivery/submission behavior
- `antispam`: Rspamd for filtering, DKIM, local-domain checks
- `redis`: shared cache/rate-limit/session dependency
- `webmail`: required webmail service selected by deployment policy
- `webdav`: required only if the selected product tier includes DAV; otherwise excluded from the supported deployment shape
- `fetchmail`: required only if external mailbox import is in the selected MVP cutline; otherwise excluded, not half-supported
- `identity`: required Authentik service/profile for OIDC login and SCIM provisioning
- `resolver`/unbound: required when DNS isolation/local resolution is part of the deployment topology
- macro scanning/oletools: required when macro scanning is enabled by the selected deployment policy

GopherMailForge should keep this split unless a concrete operational reason says otherwise.

### 5.2 Domain model to keep, cleaned up

Mailu admin models expose the core product vocabulary:

- `Domain`
- `Alternative` domain names
- `Relay`
- `User`
- `Alias`
- `Token`
- `Fetch`
- `DomainAccess`
- key/value `Config`

GopherMailForge should model these explicitly, with relational constraints and typed fields. Avoid hiding behavior in ORM magic. Domain names and emails must be normalized and validated at the boundary before storage or daemon lookup.

### 5.3 Admin/API surface to keep as concepts

Mailu exposes management for:

- domains
- alternatives/domain aliases
- users/mailboxes
- aliases
- anonymous aliases / SimpleLogin-like alias creation
- relays
- managers/domain access
- tokens
- fetchmail jobs
- admin users
- user settings/password/reply behavior
- DNS details and zonefile guidance
- DKIM generation
- language/session/UI settings

GopherMailForge should expose these as a versioned HTTP API first. A web UI can sit on top, but the API contract must not be an afterthought.

### 5.4 Internal daemon contracts to make first-class

Mailu's admin service exposes internal routes used by other services. GopherMailForge must turn these into documented internal contracts:

- Postfix domain lookup
- Postfix mailbox lookup
- Postfix alias lookup
- Postfix transport lookup
- Postfix recipient map
- Postfix sender map
- Postfix sender login authorization
- Postfix sender rate limits
- Dovecot passdb lookup
- Dovecot userdb lookup
- Dovecot quota update
- Dovecot default sieve data
- Rspamd DKIM key lookup
- Rspamd local domain list
- fetchmail list and trigger endpoints
- autoconfig/autodiscover endpoints
- auth endpoints for email/admin/user/basic checks

These endpoints are product-critical. Treat them as stable internal APIs with tests, schemas, failure semantics, and logs.

### 5.5 Config model to keep, typed

Mailu's `mailu.env` reference includes operationally important settings:

- `SECRET_KEY`
- `DOMAIN`
- `HOSTNAMES`
- `SUBNET`
- `POSTMASTER`
- `TLS_FLAVOR`
- auth rate limits
- `ADMIN`
- `WEBMAIL`
- `WEBDAV`
- `ANTIVIRUS`
- `ANTISPAM`
- `API`
- `API_TOKEN`
- `WEB_ADMIN`
- `WEB_API`
- `WEB_WEBMAIL`
- `MESSAGE_SIZE_LIMIT`
- `MESSAGE_RATELIMIT`
- `RELAYNETS`
- `RELAYHOST`
- `FETCHMAIL_ENABLED`
- `FETCHMAIL_DELAY`
- `RECIPIENT_DELIMITER`
- `DMARC_RUA`
- `DMARC_RUF`
- quota/compression/search settings
- initial admin creation settings
- OIDC provider settings: issuer, client ID, client secret reference, redirect URI, scopes, claim mapping, allowed domains, auto-provision policy

GopherMailForge should represent configuration as typed data with validation and generated environment/config files. Invalid config should fail before containers start.

### 5.6 API behavior to support deliberately

Mailu documents a REST API capable of changing configuration that the admin UI can change. It also exposes Swagger/OpenAPI and SCIM 2.0 user provisioning under `<WEB_API>/scim/v2`.

GopherMailForge should provide:

- versioned admin REST API
- OpenAPI output
- bearer-token authentication for automation
- separate internal daemon authentication boundary
- SCIM 2.0 user provisioning subset:
  - service provider config
  - resource types
  - schemas
  - users list/create/read/replace/patch/deprovision
  - groups explicitly unsupported or read-only empty until implemented
- OIDC login for administrator and user-facing web sessions, with strict issuer metadata and token validation
- required Authentik integration profile that configures OIDC and SCIM against a separately deployed Authentik service

SCIM `DELETE` should deprovision by disabling the mailbox, not by deleting mail data, unless a future destructive-delete policy explicitly says otherwise. OIDC should authenticate existing accounts and create users only under an explicit domain policy; it must not become an unbounded account-creation backdoor. Authentik is an adjacent required identity service integrated through OIDC and SCIM; it is not embedded in the mail-server trust core.

## 6. Users and use cases

### 6.1 Primary users

- self-hosting operators running one mail domain or a small number of domains
- small organizations needing mailboxes, aliases, admin delegation, DKIM/DNS help, and webmail
- identity administrators provisioning users through SCIM
- organizations using OIDC identity providers for administrator and user SSO
- operators who need Authentik managed beside the mail stack without embedding it into the control-plane binary
- advanced operators who need clear generated configs and daemon lookup behavior

### 6.2 Core use cases

1. Bootstrap a new mail server from a typed config file.
2. Generate Compose configuration and daemon configs.
3. Start the stack with predictable persistent directories.
4. Create an initial admin account safely.
5. Add a domain and get DNS records for MX, SPF, DKIM, DMARC, SRV/autoconfig.
6. Generate and rotate DKIM keys.
7. Create, disable, update, and delete mailbox users.
8. Manage aliases and aliases with multiple destinations.
9. Delegate domain management.
10. Configure relays/smarthost behavior.
11. Configure fetchmail where enabled.
12. Provision users through REST or SCIM.
13. Authenticate administrators and users through OIDC where configured.
14. Deploy/configure Authentik beside the mail stack for OIDC, SCIM, and mandatory role/domain-manager mapping.
15. Let Postfix/Dovecot/Rspamd query the control plane reliably.
16. Diagnose configuration errors before they become mail delivery failures.

## 7. Functional requirements

### 7.1 Deployment and bootstrap

- Provide a CLI for bootstrap, config validation, migration, and diagnostics.
- Generate Docker Compose files for the reference deployment.
- Generate the required Compose profile/services for Authentik integration while keeping Authentik outside the GopherMailForge binary.
- Generate daemon configuration from typed state.
- Support explicit persistent paths for data, mail, certs, DKIM keys, overrides, database, and queue/runtime state.
- Support initial admin creation with idempotent modes: create, if-missing, update.
- Refuse unsafe TLS/public-hostname combinations with clear errors where practical.

### 7.2 Configuration

- Accept a typed config file, preferably YAML or TOML.
- Validate config before writing generated files.
- Keep generated files visibly marked as generated.
- Preserve operator overrides in explicit override paths, not by editing generated files.
- Expose a dry-run diff for config generation.
- Avoid stringly typed booleans and silent coercion.

### 7.3 Database and migrations

- Use explicit migrations.
- Support SQLite for local/small deployments if it does not corrupt the design.
- Support PostgreSQL as the serious multi-user/default production database target.
- Store normalized domains and emails consistently.
- Enforce uniqueness and referential integrity at the database layer.
- Keep destructive migrations impossible without an explicit operator confirmation path.

### 7.4 Domain management

- Create, update, disable, and delete domains subject to safety policy.
- Enforce domain limits: max users, max aliases, max quota.
- Support alternative domain names.
- Generate DNS guidance for MX, SPF, DKIM, DMARC, DMARC report records, SRV/autoconfig/autodiscover, and TLSA where applicable.
- Explain generated DNS records in operator-facing output so the user can tell which record solves which mail path.
- Check whether MX records point to configured hostnames.
- Generate and rotate DKIM keys.

### 7.5 User/mailbox management

- Create, update, disable, and delete users/mailboxes.
- Store password hashes, not plaintext passwords.
- Support quota, displayed name, enabled flag, protocol enablement, spam settings, forwarding, automatic replies, and change-password-next-login semantics where applicable.
- Support application passwords/mail-client tokens because OIDC is web/session authentication, not IMAP/SMTP client authentication.
- Validate email identity fields before database lookup or storage.
- Deprovision must disable by default, not delete mail data.

### 7.6 Alias management

- Support aliases with one or more destinations.
- Support alias enable/disable.
- Support wildcard/catch-all behavior only if explicitly modeled and tested.
- Support anonymous/random alias generation only if it is inside the selected product cutline; otherwise exclude it from the supported deployment shape instead of half-supporting it.

### 7.7 Relay and transport management

- Support global relay host configuration.
- Support relay entities equivalent to Mailu's relay concept where needed.
- Generate Postfix transport answers deterministically.
- Refuse open-relay-prone configurations unless explicitly acknowledged.

### 7.8 Admin access and delegation

- Support global admins.
- Support domain managers.
- Support scoped domain access rules.
- Provide audit logs for admin mutations with actor, source path, before/after summary, timestamp, remote address, session/token identity, and OIDC subject where present.
- Separate human sessions from automation tokens.
- Support OIDC-backed login for admin and user web sessions.
- Require Authentik group/role mapping for global admins, domain managers, and scoped domain access.
- Support local-password fallback only when explicitly enabled by policy.

### 7.9 REST API

- Provide a versioned REST API for every supported admin operation.
- Generate OpenAPI schema from the actual handler/schema definitions.
- Require bearer token or stronger auth for automation.
- Return structured errors with stable codes.
- Validate all input at request boundaries.

### 7.10 SCIM API

- Support SCIM 2.0 user provisioning subset matching the useful Mailu behavior.
- Map SCIM `userName` to mailbox email address.
- Map `displayName` and `name.formatted` to displayed name.
- Map `active` to enabled/disabled.
- Accept password only as a string.
- Reject malformed JSON, non-object payloads, invalid scalar identity fields, unsupported patch operations, and unknown paths.
- Cap list results to the advertised maximum.
- Treat groups as unsupported until real group semantics exist.

### 7.11 OIDC authentication

- Support OpenID Connect for administrator and user web login.
- Discover provider metadata from the configured issuer and require issuer metadata to be present and valid.
- Validate ID token issuer, audience, authorized party (`azp`) when present, subject, expiry, issued-at, and not-before claims.
- Reject malformed or unverifiable tokens; never fall back to trusting unsigned claims.
- Map OIDC identities to mailbox/admin accounts through explicit claim mapping.
- Support allowed-domain and allowed-group policy before granting access.
- Support just-in-time user creation only when the domain already exists and policy explicitly enables it.
- Keep OIDC login separate from daemon password/token authentication; mail clients still need Dovecot-compatible credentials or application tokens.
- Provide first-class Authentik integration through generated OIDC client settings, SCIM provider settings, redirect URLs, group/role mappings, and documented secret handling.
- Treat Authentik as a required adjacent service for identity flows: if Authentik is unavailable, new SSO/provisioning actions may fail, but mail delivery and daemon lookup paths must continue to function.
- Provide clear login failure logs without exposing tokens or secrets.

### 7.12 Authentik integration profile

- Support a required Authentik deployment/profile for identity infrastructure beside the mail stack.
- Generate or document Authentik OIDC application/client configuration for GopherMailForge web login.
- Generate or document Authentik SCIM provider configuration for mailbox provisioning.
- Generate or document mandatory Authentik group/role mapping for global admins, domain managers, and scoped domain access.
- Keep Authentik data, secrets, upgrades, and availability independent from the mail control-plane database and daemon lookup paths.
- Provide bootstrap/recovery paths that do not depend on Authentik being healthy.
- Do not proxy every identity operation through custom glue when standard OIDC and SCIM contracts already solve the problem.

### 7.13 Internal daemon APIs

- Provide stable endpoints for Postfix, Dovecot, Rspamd, fetchmail, auth, and autoconfig.
- Make lookup behavior testable without running the full mail stack.
- Provide a daemon lookup debugger that explains Postfix recipient/sender decisions, Dovecot auth/userdb decisions, alias expansion, domain matching, and Rspamd local-domain/DKIM answers.
- Log lookup failures with enough context to debug without exposing secrets.
- Use explicit auth/trust boundaries for internal endpoints.

### 7.14 Background jobs

- Treat background work as a first-class system:
  - DKIM generation/rotation
  - config regeneration
  - fetchmail polling
  - DMARC report jobs if supported
  - cert renewal integration hooks if supported
  - cleanup/maintenance jobs
- Jobs must have state, logs, retry policy, and operator visibility.

### 7.15 Web UI

- Web UI is useful but not the primary contract.
- The UI must use the same public admin API where practical.
- Do not hide capabilities in UI-only routes.
- Support core admin flows: domains, users, aliases, relays, tokens, DNS details, DKIM, managers, and settings.


### 7.16 Diagnostics and doctor commands

- `gophermailforge doctor` must check DNS records, exposed ports, TLS certificate state, DKIM presence/validity, database reachability, Authentik reachability, and daemon lookup health.
- Doctor output must distinguish configuration errors, external DNS/TLS state, daemon reachability, and identity-provider failures.
- Doctor checks must be safe to run repeatedly and must not mutate production state.
- Provide focused subcommands for DNS, TLS, DKIM, Authentik, database, Postfix, Dovecot, Rspamd, and generated-config checks.
- Provide machine-readable output for automation and human-readable output for operators.

### 7.17 Contract-test harness

- Provide a contract-test harness before UI work is considered complete.
- Cover Postfix maps, Dovecot passdb/userdb, Rspamd local domains and DKIM, SCIM behavior, OIDC token validation, Authentik role mapping, and config rendering.
- Tests must run without a full mail stack where possible; end-to-end smoke tests cover the integrated stack separately.
- Contract tests must include failure paths, not just happy-path lookups.

### 7.18 Mail delivery smoke test

- Provide a safe smoke-test command that creates or uses a test domain/user/alias, sends test mail, verifies delivery, verifies IMAP login, and verifies DKIM signing.
- Smoke tests must clean up or clearly report any test artifacts they create.
- Smoke tests must fail loudly when mail is accepted but not delivered, delivered without DKIM, or authenticated through the wrong path.

### 7.19 Rollback and reference snapshots

- Store known-good reference snapshots for generated config, migration version, image versions, and selected deployment policy.
- Provide rollback guidance from the last known-good snapshot.
- Do not claim rollback is available for destructive data migrations unless the database backup/export exists and has been verified.

### 7.20 Mailu import

- Provide a Mailu import path after the core schema is stable.
- Import domains, users, aliases, relays, DKIM keys, and compatible tokens where possible.
- Import must validate data before writing and must produce a report of imported, skipped, incompatible, and manually required items.
- Import must not silently weaken passwords, DKIM permissions, role mappings, or daemon lookup behavior.


### 7.21 Version 5 notifications and operator messaging

- Provide a version 5 notifications/operator-messaging layer after the core admin/control plane is stable, with Telegram as the first required channel.
- Telegram notifications must cover doctor failures, certificate renewal failures, backup verification failures, queue/deferred-mail alerts, abuse/rate-limit alerts, and other high-priority operational events.
- Telegram commands must start read-only: doctor summary, queue summary, domain health summary, backup status, and deployment status.
- Telegram approval workflows may later approve bounded actions such as config apply, DKIM rotation, queue flush/retry, rollback, and emergency/break-glass use.
- Every Telegram-triggered action must pass through the same core authorization, policy, validation, and audit paths as UI/API/CLI actions.
- Telegram actors must be mapped to configured identities; raw chat membership is not authorization.
- Telegram messages must never include secrets, full tokens, private keys, passwords, or unredacted before/after values.
- Telegram is not the authority. The control plane owns policy, permissions, state transitions, and audit.

## 8. Security requirements

- No unauthenticated admin API.
- OIDC must validate issuer metadata, signatures, subject, audience, authorized party, expiry, issued-at, and not-before claims before session creation.
- OIDC client secrets must be stored as secrets, not ordinary generated config.
- Authentik integration must not weaken local recovery access, daemon authentication, or mail delivery availability.
- Separate external admin/API auth from internal daemon auth.
- API tokens must be hashable/revocable where practical.
- Passwords must use a modern password hashing scheme compatible with Dovecot/Postfix auth needs.
- Validate identity fields before database access.
- Prevent open relay by default.
- Rate-limit authentication attempts.
- Support TLS modes equivalent to manual certs and Let's Encrypt integration.
- Store DKIM private keys with constrained filesystem permissions.
- Avoid logging secrets, passwords, full tokens, or private keys.
- Destructive actions require explicit confirmation in UI/API/CLI and any future Telegram approval workflow.

## 9. Operational requirements

- `gophermailforge config validate` must catch bad config before deployment.
- `gophermailforge config render --diff` must show generated changes.
- `gophermailforge migrate` must show pending migrations and apply them explicitly.
- `gophermailforge doctor` must check DNS, ports, database, daemon reachability, certs, DKIM, generated files, Authentik reachability, and daemon lookup health.
- `gophermailforge lookup explain` must explain recipient, sender, alias, domain, Dovecot auth/userdb, and Rspamd DKIM/local-domain decisions.
- `gophermailforge smoke mail` must exercise SMTP submission, delivery, IMAP login, alias delivery, and DKIM signing in a bounded test path.
- `gophermailforge snapshot` must capture known-good generated config, migration version, image versions, and deployment policy.
- Operational alerts must have a notification abstraction that can support Telegram without letting messaging transport own policy or authorization.
- Support backup/export of control-plane state.
- Support restore/import with validation.
- All generated configs should be reproducible from database + typed config.
- Every daemon-facing lookup should be observable.


## 10. Plugin boundaries

Pluggability is allowed only at narrow mechanism seams. The control plane must not become a plugin swamp before the mail server works.

### 10.1 Pluggable seams

1. Webmail provider
   - Roundcube
   - SnappyMail
   - future custom GopherMailForge webmail
   - Webmail is a mail client; the provider seam must not own mailbox/domain policy.

2. DNS provider integration
   - Cloudflare
   - Route53
   - manual/export-only
   - RFC2136 where practical
   - DNS providers may create or verify records; core decides which records are required, safe, audited, and allowed.

3. ACME/certificate backend
   - Let's Encrypt
   - manual certificates
   - internal/dev certificates
   - Interface must stay small: issue, renew, inspect. Production must not silently fall back to self-signed certificates.

4. Backup storage backend
   - local filesystem
   - S3-compatible storage
   - restic/borg wrapper where justified
   - Backup verification remains core behavior, not a storage-plugin promise.

5. Notification backend
   - Telegram as the first required implementation
   - email
   - webhook
   - Slack/Discord/etc later
   - Notification backends may deliver alerts and approval prompts; they must not own authorization, mutation, confirmation, or audit.

6. Import source
   - Mailu first
   - Docker-mailserver later if justified
   - raw Postfix/Dovecot config later if justified
   - Import plugins may parse source systems; core validates and decides what may enter GopherMailForge state.

### 10.2 Not pluggable early

The following are the spine of the product and must not be made pluggable during the early architecture:

- Postfix/Dovecot/Rspamd contracts
- audit logging
- permission model
- Authentik role mapping
- config rendering core
- database/migration layer
- daemon lookup debugger

Making these pluggable early is architecture cosplay. These surfaces define trust, state, compatibility, and diagnosability. They stay core until the mechanism is proven and the cost of abstraction is justified.

### 10.3 Plugin rule

Core owns policy. Plugins provide mechanisms.

Examples:

- A DNS plugin may say, "Cloudflare can create this DNS record."
- Core decides whether that record is required, safe, audited, and allowed.
- A notification plugin may deliver an approval prompt.
- Core decides whether the actor is authorized, whether confirmation is valid, whether the action mutates state, and what audit event is written.

No plugin may bypass validation, authorization, confirmation, audit logging, redaction rules, or generated-config apply gates.

## 11. Compatibility strategy

### 11.1 Mailu compatibility to preserve

Preserve where valuable:

- Compose-oriented deployment model
- Mailu domain/user/alias/relay/fetch concepts
- DNS guidance semantics
- DKIM lifecycle expectations
- SCIM user provisioning shape
- OIDC administrator/user SSO as a first-class authentication path
- required Authentik sidecar/profile integration through OIDC, SCIM, and group/role mapping
- REST API coverage in spirit, not necessarily exact broken edge behavior
- internal daemon lookup semantics needed by Postfix/Dovecot/Rspamd

### 11.2 Mailu compatibility to reject

Reject:

- permissive scalar coercion for identity values
- hidden fake success/no-op API behavior
- untyped environment sprawl as the core config model
- UI-only behavior with no API equivalent
- implicit ORM behavior as a contract
- accidental historical route shapes when a cleaner versioned API is available

## 12. Milestones

### M0: Reference inventory

- Complete Mailu route/model/config/template inventory.
- Document daemon-facing contracts.
- Document generated config responsibilities.
- Decide database target policy: PostgreSQL-first with SQLite-compatible subset, or strict PostgreSQL.

### M1: Core schema and CLI skeleton

- Go module and repository structure.
- Config parser/validator.
- Database schema and migrations.
- Domain, user, alias, relay, token primitives.
- Application password/mail-client token primitive.
- CLI: validate, migrate, doctor, render.

### M2: Internal daemon contract MVP

- Postfix lookup endpoints.
- Dovecot passdb/userdb endpoints.
- Rspamd local-domain/DKIM endpoints.
- Daemon lookup debugger for recipient, sender, alias, domain, Dovecot auth/userdb, and Rspamd DKIM/local-domain answers.
- Contract tests for lookup behavior and failure paths.
- Generated config fragments for the reference services.

### M3: Admin API MVP

- Versioned REST API.
- OpenAPI output.
- Token auth.
- Domain/user/alias management.
- Validation and structured errors.

### M4: Compose deployment MVP

- Generated Docker Compose reference stack.
- Persistent directory layout.
- Initial admin bootstrap.
- Config doctor for DNS, ports, TLS, DKIM, database, Authentik, generated config, and daemon lookup health.
- End-to-end smoke path: SMTP submission, receive, alias delivery, DKIM signing, authenticate, IMAP login.
- Known-good snapshot capture for generated config, migration version, image versions, and deployment policy.

### M5: OIDC MVP

- OIDC provider configuration.
- Required Authentik profile documentation/generation.
- Provider discovery and JWKS handling.
- Strict ID token validation.
- Claim mapping to existing users/admins.
- Policy-gated just-in-time user creation.
- Authentik-compatible login path.
- Authentik outage does not break existing mail delivery or daemon lookup paths.

### M6: SCIM MVP

- SCIM service provider config, resource types, schemas.
- User list/create/read/replace/patch/deprovision.
- Strict validation tests.
- Authentik-compatible provisioning path.
- Authentik profile can provision users through SCIM without bypassing GopherMailForge validation.
- Authentik group/role mapping is verified for global admins, domain managers, and scoped domain access.

### M7: Web UI MVP

- Admin login/session.
- Domain/user/alias/token/DNS/DKIM screens.
- Doctor/diagnostic result views.
- Audit log views.
- UI backed by API, not hidden side routes.

### M8: Mailu import MVP

- Import domains, users, aliases, relays, DKIM keys, and compatible tokens where possible.
- Produce imported/skipped/incompatible/manual-action report.
- Verify imported data through daemon contract tests before calling the import successful.

### M9: Version 5 notifications MVP

- Notifications backend for high-priority operational alerts, with Telegram as the first required channel.
- Read-only Telegram commands for doctor summary, queue summary, domain health, backup status, and deployment status.
- Telegram approval workflow for bounded high-risk actions after authorization/policy/audit paths are proven.
- Telegram actor-to-identity mapping.
- Audit coverage for every Telegram-triggered action.

## 13. Success metrics

- A fresh operator can bootstrap a working Compose mail stack from typed config.
- Postfix, Dovecot, and Rspamd can run against GopherMailForge internal APIs without Mailu's Python admin service.
- Domain/user/alias operations work through CLI and REST API.
- OIDC login can authenticate administrators/users through a compliant identity provider without weakening local/session security.
- Authentik deployment/configuration works as an adjacent required service, not an embedded control-plane dependency.
- Authentik group/role mapping assigns global admin, domain manager, and scoped domain access without local manual edits.
- SCIM provisioning can create, update, disable, and list users through an identity provider.
- Generated DNS guidance covers MX, SPF, DKIM, DMARC, DMARC report records, SRV/autoconfig/autodiscover, and TLSA where applicable.
- Doctor identifies DNS, TLS, DKIM, database, Authentik, generated-config, and daemon lookup failures without mutating state.
- Daemon lookup debugger explains Postfix, Dovecot, Rspamd, alias, and domain decisions.
- Application passwords/mail-client tokens allow mail clients to authenticate without pretending OIDC is an IMAP/SMTP protocol.
- Generated config is reproducible and inspectable.
- Known-good snapshots exist for generated config, migration version, image versions, and deployment policy.
- Core behavior is covered by unit/contract tests without requiring the full stack.
- End-to-end smoke tests prove SMTP submission, SMTP receive, IMAP login, alias delivery, DKIM signing, and spam/local-domain behavior.
- Mailu import can move supported state without silent data loss or behavior weakening.
- Telegram can deliver operational alerts and read-only status without bypassing core policy, authorization, or audit boundaries.

## 14. Risks and hard problems

- Mail delivery failures are often config-generation failures disguised as daemon problems; doctor and lookup explain commands are mandatory, not nice-to-have tools.
- Dovecot/Postfix lookup semantics must be exact; vague compatibility will break mail flow.
- DKIM key handling crosses database and filesystem state; sloppy ownership will create security and backup problems.
- Supporting SQLite and PostgreSQL can create lowest-common-denominator schema garbage if not constrained.
- OIDC looks simple until token validation is sloppy; issuer, audience, azp, subject, expiry, issued-at, and not-before checks are not optional.
- Bundling Authentik too tightly would turn identity outages/upgrades into mail-server outages. It is required for identity flows, but the boundary must stay clean.
- SCIM looks small but punishes weak validation.
- Compose generation can become a templating swamp unless the config model is kept strict.
- Web UI work can distract from the real contract: daemon APIs, generated config, diagnostics, and contract tests.
- Mailu import can import historical garbage if validation and reporting are weak.
- Telegram can become an unaudited remote-control backdoor if actor mapping, confirmations, and policy checks are not centralized in the control plane.

## 15. Open decisions

1. Database policy: PostgreSQL-first, SQLite dev-only, or true dual support?
2. Config file format: YAML, TOML, or both?
3. Initial UI technology: server-rendered Go templates or separate frontend?
4. Token model: single global API token compatibility, scoped tokens, or both?
5. Mailu migration/import: support importing existing Mailu database/config in MVP or later?
6. How much REST API compatibility with Mailu v1 is worth preserving?
7. Whether anonymous alias/SimpleLogin-like behavior belongs in MVP.
8. Whether fetchmail belongs in MVP or is excluded from the initial supported deployment shape.
9. Whether OIDC just-in-time user creation belongs in MVP or should require pre-created users only.
10. Which OIDC claim mapping is canonical: email, preferred_username, subject-bound external identity, or an explicit configured claim.
11. Whether the required Authentik profile should generate configuration artifacts only, run Authentik containers, or support both modes.
12. Which Authentik groups/roles are canonical for global admin, domain manager, and scoped domain access.
13. Which webmail service is the default required deployment target.
14. Which doctor checks are blocking versus warning-only.
15. What snapshot retention and rollback guarantees are actually supported.
16. Which Mailu token/password artifacts can be safely imported without weakening authentication.
17. Which Telegram actions remain notification-only, which are read-only commands, and which may become approval workflows.
18. Which Telegram identity mapping is canonical: configured chat IDs, linked user accounts, Authentik identities, or a combination.

## 16. Acceptance criteria for starting architecture

Architecture work may begin when this PRD has been followed by:

- a Mailu reference inventory document
- an internal daemon API contract document
- a data model document
- a generated config responsibility map
- a deployment topology document
- an explicit MVP cutline

Do not jump straight into coding. That is how control planes become piles of accidental behavior.
