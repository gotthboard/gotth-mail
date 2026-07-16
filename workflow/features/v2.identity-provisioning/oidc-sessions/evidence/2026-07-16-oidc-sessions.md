# v2 OIDC sessions evidence

Date/time: 2026-07-16 11:05 CDT

Commit: current commit; hash assigned by Git after commit

## Scope implemented

Completed `v2.identity-provisioning.oidc-sessions`.

Implemented:

- OIDC provider discovery document validation:
  - issuer match;
  - authorization endpoint present;
  - token endpoint present;
  - JWKS URI present;
  - authorization-code response type support;
  - RS256 ID-token signing support.
- Login-start state:
  - random state ID;
  - random nonce;
  - browser binding hash;
  - redirect-after-login storage;
  - expiration.
- Authorization URL generation with response type, client id, exact redirect URI, state, nonce, and scope.
- Callback validation:
  - exact redirect URI match;
  - state exists;
  - state unexpired;
  - state unused;
  - browser binding hash matches;
  - state is marked used atomically with callback acceptance.
- ID token validation:
  - rejects unsigned `alg=none` fallback;
  - requires RS256 header and key id;
  - verifies signature against configured JWKS RSA key;
  - issuer match;
  - stable non-empty subject;
  - audience contains client ID;
  - `azp` matches client ID when present;
  - `exp`, `iat`, `nbf` checked with bounded clock skew;
  - nonce match.
- Session creation:
  - OIDC auth method;
  - identity reference based on issuer and subject;
  - expiry and last-seen timestamps;
  - CSRF secret hash.
- API surfaces:
  - `GET /api/v1/oidc/login` requires browser binding and returns login start data;
  - `POST /api/v1/oidc/callback` validates callback data and returns bounded identity/session output.
- Safe OIDC error strings that do not disclose token values.

## Tests added

- valid OIDC callback creates session;
- login state is single-use;
- wrong browser binding rejected;
- wrong redirect URI rejected;
- nonce mismatch rejected;
- unsigned token rejected;
- issuer/subject/audience/azp/exp/iat/nbf claim failures rejected;
- discovery validation rejects bad issuer;
- token response validation rejects unsigned fallback;
- safe error handling redacts token-looking errors;
- login URL contains required OIDC parameters;
- API login route rejects missing browser binding.

## Verification

```text
go test ./...
git diff --check -- .
```

## Explicit gaps / next child

This child does not implement Authentik role mapping, SCIM provisioning, app-passwords, or identity UI. Those are separate v2 children. The next active child is `v2.identity-provisioning.authentik-roles-authz`.
