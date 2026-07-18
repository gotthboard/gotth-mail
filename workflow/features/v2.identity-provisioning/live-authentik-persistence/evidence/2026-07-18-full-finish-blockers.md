# v2 full-finish blockers

Status: planned/incomplete after full-finish audit.

Required before v2 can honestly return to done:

- Live Authentik authorization-code smoke using a real provider/app/group setup.
- Durable OIDC login state and sessions, with restart/concurrency tests.
- Durable SCIM mailbox/token/app-password storage and Dovecot restart proof.
- App-password client compatibility matrix.
- Honest password verifier contract: PBKDF2-only or true Django/Authenik hasher compatibility.

Current repair closed immediate auth holes and added durable schema contracts, but does not claim these live integrations are complete.
