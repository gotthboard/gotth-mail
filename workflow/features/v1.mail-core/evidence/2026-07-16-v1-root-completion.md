# v1 Mail Core root completion evidence

Date/time: 2026-07-16 09:03 CDT

Commit: current commit; hash assigned by Git after commit

## Scope completed

Finished `v1.mail-core` after the final cold admission review found remaining scope and evidence blockers.

Implemented or corrected:

- deterministic SMTP reference smoke harness using Python `smtplib` instead of brittle sleep/`nc` DATA scripting;
- `gmf doctor --format text|json` CLI;
- mail admin UI and CRUD backing store for domains, users, and aliases;
- DNS/DKIM, doctor, lookup debugger, and plugin status/config screens in the server-rendered admin shell;
- seam-specific first-plugin services for DNS export, certificate/manual ACME failure, backup verification, and Roundcube webmail provider config;
- reference runtime doctor proof for loud ACME/manual-cert failure and plugin health;
- historical changelog/evidence commit-hash cleanup;
- `workflow.toml` root state updated to `done`.

## Evidence expectation

Final verification must pass:

```text
go test ./...
git diff --check -- .
scripts/reference-runtime-smoke.sh
```

## Remaining explicit non-v1 scope

- production issuance against a real public domain remains deployment/environment-specific; v1 proves loud failure in the reference runtime instead of pretending issuance for `example.test`;
- custom webmail implementation remains v4; v1 uses selected external Roundcube provider proof;
- identity provisioning remains v2.
