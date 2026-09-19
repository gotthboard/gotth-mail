# GOTTH Extensions foundation adoption

State: `in_progress`

Candidate implementation pins reviewed `gotth-extensions` commit `3822dd7`
and reconciles only GOTTH Mail's shared manifest, exact grant, negotiation,
lifecycle, authenticated handshake, and health mechanics. Mail's seam
protocols, transport credentials, secret values, routing, supervision,
mutation, audit, update, rollback, and product authority remain Mail-owned.

The candidate retains the existing Mail plugin service for userspace
compatibility and adds the narrow upstream foundation control service beside
it. Completion requires the recorded full/race/vet/container gates and cold
review; the later Extensions administrator remains a separate feature.
