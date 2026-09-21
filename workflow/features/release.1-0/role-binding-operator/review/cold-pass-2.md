# Cold review 2

## Decision

FINDINGS FIXED.

The product mechanism was sound, but the evidence did not prove two explicit
contracts: revoke after disabled state and the direction of grant/revoke audit
snapshots. PostgreSQL tests now prove disabled mailbox-domain and target-domain
grant rejection, revoke recovery after disable, grant state in `after`, revoke
state in `before`, and null opposite snapshots.
