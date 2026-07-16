# Authentik role mapping and permission simulator evidence

Feature: `v2.identity-provisioning.authentik-roles-authz`
Timestamp: 2026-07-16 11:52 CDT

## Scope

Implemented the v2 Authentik role-mapping authorization surface and permission simulator coverage.

## Changes

- Added Authentik-backed OIDC group mapping to authorization actors.
- Added explicit roles:
  - `global_admin`
  - `domain_manager`
  - `scoped_domain_access`
- Added verified role mapping records with Authentik group, role, optional domain, and verification state.
- Added allow/deny explanations with matched rules and missing requirements.
- Added simulator coverage for all actor classes required by the v2 spec:
  - local admin
  - API token
  - OIDC subject
  - SCIM client
  - system actor
  - break-glass actor
  - plugin service actor
  - global admin
  - domain manager
  - scoped domain access
  - denied results
- Changed `/api/v1/authz/explain` so it evaluates the submitted actor/action/resource request instead of returning a hardcoded local-admin explanation.
- Added doctor validation for required Authentik role mappings.

## Verification

- `go test ./internal/authz` passed.
- `go test ./internal/api ./internal/authz` passed.
- `go test ./internal/ops ./internal/api ./internal/authz` passed.
- `git diff --check -- .` passed.
- `go test ./...` passed.

## Coverage gaps

No accepted coverage gap for this feature surface.
