# v3 full-finish blockers

Status: in_progress/incomplete after full-finish audit and v2 interactive blocker.

Required before v3 can honestly return to done:

- Real isolated backup restore and durable backup verification records.
- Live-compatible Mailu import parser/plugin path and canonical adoption into durable state.
- SQL-backed audit query/read/redaction path and real retention.
- Canonical bulk mutations against mailbox/alias/domain storage.
- Persisted snapshots linked to verified backup state.

Current repair closed immediate audit/UI auth bypasses and removed fake UI backup success, but does not claim production operations are complete.
