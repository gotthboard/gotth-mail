# OpenPGP Exact Sender Reference Drafts

These drafts are project reference material for GopherMailForge's mandatory exact-sender OpenPGP/MIME signing requirement.

- [Exact Sender Identity Binding for OpenPGP/MIME Signed Email](draft-hunn-openpgp-exact-sender-signatures-01.md) defines the core profile: DKIM is not exact sender proof, outbound email is OpenPGP/MIME signed, signing keys resolve to exactly one active sender identity, mismatches fail closed, and delegation is explicit.
- [Operational Identity History and Audit Indexing for Exact Sender Binding](draft-hunn-exact-sender-operational-identity-history-00.md) defines the companion operational model for temporal identity state, address/name history, search/audit indexing, downgrade detection, key-rotation continuity, and forensic export.

The drafts are not a substitute for implementation evidence. GopherMailForge PRDs, architecture, implementation specs, tests, and workflow evidence still define what is implemented in each version.
