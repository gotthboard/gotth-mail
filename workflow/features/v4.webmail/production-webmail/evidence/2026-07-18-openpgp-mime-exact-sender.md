# v4 OpenPGP/MIME exact-sender signing evidence

Status: real local OpenPGP/MIME signing and exact-sender verification implemented and container-smoke covered.

## Scope

Close the fake-signing gap for v4 webmail send flow:

- produce RFC3156-style `multipart/signed` mail with `protocol="application/pgp-signature"` and `micalg=pgp-sha256`;
- use the maintained ProtonMail OpenPGP fork, not the deprecated `golang.org/x/crypto/openpgp` API;
- fail closed on signing identity mismatch;
- verify the detached signature with the public keyring;
- verify exact sender binding against the visible outer From, signing fingerprint, and signed sender-binding assertion headers.

## Implementation

- Added `webmail.OpenPGPMIMESigner`.
- Added `webmail.OpenPGPMIMEVerifier`.
- The signer:
  - requires a private OpenPGP entity;
  - checks the requested `Identity` fingerprint against the signing key fingerprint;
  - checks the original message From against the exact sender identity before signing;
  - signs the exact MIME entity bytes emitted as the first `multipart/signed` part;
  - includes signed `X-GopherMailForge-Signed-From` and `X-GopherMailForge-Signing-Fingerprint` assertions inside the signed MIME entity.
- The verifier:
  - parses the `multipart/signed` structure instead of string-grepping it;
  - verifies the armored detached signature with the configured public keyring;
  - checks visible outer From, signed From assertion, key fingerprint, and expected identity all match.
- `ValidateOpenPGPMIME` now delegates to the parser-backed split instead of accepting loose substring matches.
- The containerized webmail SMTP smoke now runs the real OpenPGP/MIME signing/verification tests in `test-runner`.

## Verification

- `go test -count=1 ./internal/webmail` passed locally during implementation.
- `scripts/containerized-webmail-smtp-smoke.sh` now runs:
  - live Compose SMTP submission through Postfix;
  - real OpenPGP/MIME signer/verifier tests;
  - sender mismatch rejection;
  - fingerprint mismatch rejection;
  - tampered signed-part rejection.

## Remaining blockers

- Production key storage/unlock policy and operator key lifecycle are still deployment decisions.
- v4 no longer treats unsigned/fake-signed webmail submission as acceptable in the core sender path.
