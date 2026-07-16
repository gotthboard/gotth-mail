# v3 Mailu import evidence

Feature: `v3.ops-import-admin.mailu-import`
Timestamp: 2026-07-16 12:45 CDT

## Scope

Implemented Mailu import preview/apply admission model with server-side stored previews, source fingerprint, preview hash, actor binding, expiry, incompatible/manual-review item rejection, daemon verification before success, import lookup, and audit.

## Verification

- `go test ./internal/ops` covers supported import preview/apply, actor mismatch rejection, and plaintext secret weakening rejection.
- `go test ./internal/api` covers Mailu preview/get/apply API binding using stored preview IDs rather than caller-supplied preview bodies.
- `go test ./...` passed before state admission.
- `git diff --check -- .` passed before state admission.

## Coverage gaps

No accepted coverage gap for this feature surface.
