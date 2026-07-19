# v3 containerized Mailu import smoke evidence

Status: repo-owned container fixture added and verified.

## Scope

Move the Mailu import compatibility fixture into the project Compose topology instead of relying on an ad hoc host-local `/tmp/gmf-mailu-fixture` stack. This is for GopherMailForge import compatibility only, not production Mailu deployment.

## Implementation

- Added `test-runner` service to `compose/reference/docker-compose.yml` using the Dockerfile `build` target so project tests can run inside the container build/runtime environment.
- Added Mailu import fixture services behind Compose profile `mailu-import`:
  - `mailu-redis`
  - `mailu-admin` using `ghcr.io/mailu/admin:2.0`
  - isolated Mailu volumes for `/data`, `/dkim`, and Redis state
- Mailu fixture does not publish public mail ports and does not attempt DNS/TLS/SMTP production deployment.
- Added `scripts/containerized-mailu-import-smoke.sh`:
  - starts only the Mailu import fixture profile;
  - waits for Mailu admin health;
  - seeds `example.test`, `user@example.test`, and `alias@example.test`;
  - exports redacted and secret Mailu config to a temporary directory, not checked-in fixtures;
  - runs `go test -count=1 ./internal/ops ./internal/api` inside the Compose `test-runner` container;
  - validates the live secret export shape includes top-level `domain`, `user`, `alias`, `relay`, Mailu Passlib `$bcrypt-sha256$` user hashes, and the expected multi-target alias.
- Added contract coverage so Compose cannot silently lose the test runner, Mailu fixture services/profile, or smoke-script checks.

## Verification

- `sudo docker compose -f compose/reference/docker-compose.yml --profile mailu-import --profile test config` passed.
- `go test -count=1 ./test/contract ./internal/ops ./internal/api` passed.
- `git diff --check -- .` passed.
- `go test -count=1 ./...` passed.
- `scripts/containerized-mailu-import-smoke.sh` passed, including container build-stage `go test ./...`, containerized focused import/API tests, and live Mailu export shape checks.

## Remaining blockers

- This removes the ad hoc host Mailu fixture as a blocker for v3 Mailu import compatibility checks.
- It does not remove the v2 live Authentik browser/passkey/group-claim blocker.
- It does not implement production Mailu deployment; that is intentionally out of scope.
