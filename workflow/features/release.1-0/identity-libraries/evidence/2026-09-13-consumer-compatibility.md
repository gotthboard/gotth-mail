# GOTTH identity-library compatibility evidence — 2026-09-13

## Verdict

`gotth-oidc` and `gotth-scim` fit GOTTH Mail at their documented reusable
boundaries. They do not replace consumer-owned state, policy, or persistence.

## Exact inputs

- `github.com/gotthboard/gotth-oidc`
  `v0.0.0-20260906064525-1b84c0780850`, module checksum
  `h1:1bxYUa3mOZoZWIGX1hDine9Q0Ytzusy/X/LYtLg40aI=`;
- `github.com/gotthboard/gotth-scim`
  `v0.0.0-20260906064525-774fe1bc2057`, module checksum
  `h1:MinTFBkByQtonDaMjEepfrRlC05moX9kPqxrIDTbowg=`.

The exact main commits agree between canonical Forgejo and public GitHub:

- OIDC: `1b84c07808506bbb1e194abc84005739251f66e3`;
- SCIM: `774fe1bc20576a9dc0701160a18582b6b4e3f84e`.

## Executed compatibility proof

The external GOTTH Mail consumer test:

- performed real OIDC discovery through the library's bounded transport;
- began an Authorization Code request and verified state, nonce, S256 PKCE,
  and protected attempt context were present; and
- constructed the SCIM server through its public API, authenticated an opaque
  scope, created a User, proved the assigned resource ID is opaque rather than
  the mailbox address, and read the resource back.

Focused, full, and race suites passed. This evidence admits the module pins and
public APIs only.

## Remaining consumer work

- replace the duplicate in-tree OIDC protocol code with protected-attempt and
  session adapters while preserving public routes;
- resolve roles from durable provisioned state instead of granting authority
  to arbitrary token claims;
- implement and pass the SCIM transactional store conformance suite;
- migrate email-address SCIM IDs to opaque persistent IDs;
- commit mailbox projection, password delegation, audit, daemon sync, and
  session effects atomically; and
- prove live Authentik login, provisioning, role, deprovisioning, restart,
  backup, and restore behavior.

The libraries remain untagged because their contracts require a real consumer
pin plus an owner license decision. Compatibility evidence does not invent
either.
