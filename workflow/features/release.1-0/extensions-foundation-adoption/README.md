# GOTTH Extensions foundation adoption

State: `done`

Implementation commit `3102db3` pins reviewed `gotth-extensions` commit `3822dd7`
and reconciles only GOTTH Mail's shared manifest, exact grant, negotiation,
lifecycle, authenticated handshake, and health mechanics. Mail's seam
protocols, transport credentials, secret values, routing, supervision,
mutation, audit, update, rollback, and product authority remain Mail-owned.

The implementation retains the existing Mail plugin service for userspace
compatibility and adds the narrow upstream foundation control service beside
it. The recorded full/race/vet/container gates passed and two fresh admission
passes were clean on the same commit. The later Extensions administrator
remains a separate feature.
