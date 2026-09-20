# Production artifacts

State: `done`

Builds the five immutable production role images, strict deterministic
configuration archive and release manifest, NGINX mail-front authentication
contract, fixed entrypoints/health checks, and disposable replacement proof.

The reference Compose stack, Mailu, Roundcube, development credentials,
self-signed fallback, runtime package installation, and Telegram fixtures are
excluded. The independently packaged webhook extension remains the admitted
notification implementation.

Exact build, mail-flow, reproducibility, Stack replacement/rollback, and cold
review records are under `evidence/` and `review/`. Completion admits this
artifact mechanism only; it does not publish an alpha or claim live deployment.
