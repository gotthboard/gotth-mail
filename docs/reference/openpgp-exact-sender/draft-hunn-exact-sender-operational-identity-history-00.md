---
title: "Operational Identity History and Audit Indexing for Exact Sender Binding"
abbrev: "Exact Sender Operational Identity"
docname: "draft-hunn-exact-sender-operational-identity-history-00"
category: "info"
ipr: "trust200902"
area: "Security"
workgroup: "Internet Engineering Task Force"
keyword: ["OpenPGP", "email", "identity history", "audit", "search"]
stand_alone: true

author:
  - fullname: "Danny Hunn"
    organization: "Independent"
    email: "daniel@dannyhunn.com"

normative:
  RFC2119:
  RFC8174:

informative:
  RFC2104:
  RFC3156:
  RFC5322:
  RFC6376:
  RFC8259:
  RFC9580:
--- abstract

This document defines operational guidance for identity history, search, audit indexing, downgrade detection, key-rotation continuity, and forensic evidence export for systems that implement exact sender identity binding for OpenPGP/MIME signed email.  It is a companion to `draft-hunn-openpgp-exact-sender-signatures` and intentionally focuses on local or enterprise identity state rather than a public Internet-wide identity database.

--- middle

# Introduction

Exact sender binding can prove more than a display name or email address.  It can bind a message to a stable local Sender Identity, a signing key fingerprint, a delegation record, and the policy state in force when the message was sent.  That creates useful operational capabilities: historical search across name changes, address reuse protection, downgrade alerts, key-rotation continuity, and forensic export.

This document does not define a new OpenPGP/MIME signature format and does not require public receivers to understand private enterprise identity state.  It describes how Conforming Archives, Auditors, Senders, and local Verifiers can preserve and use that state.

# Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14 {{RFC2119}} {{RFC8174}} when, and only when, they appear in all capitals.

Sender Identity:
: A configured user, service, role mailbox, or system identity that is permitted by local policy to assert one or more RFC 5322 addresses.

Signing Key:
: An OpenPGP key or certificate capable of producing an OpenPGP/MIME signature.

Identity Class:
: The local class of a Sender Identity, such as human user, service, role mailbox, automation, delegated assistant, contractor, guest, or service-only identity.

Delegation Record:
: A versioned local authorization record that permits one Sender Identity, service identity, role identity, or Signing Key to send on behalf of another Sender Identity for a defined scope and lifetime.

Identity Timeline:
: A time-bounded record of the identity, key, delegation, address, role, authority, lifecycle, and policy state relevant to sender binding.

Search Token:
: A local index value derived from exact sender binding fields for search or audit lookup.

Forensic Evidence Bundle:
: A preserved set of message, signature, identity, policy, and verification evidence sufficient to review an exact sender decision.

# Scope

This document applies to local or enterprise systems that already implement or consume exact sender binding results.  It does not claim that a generic public receiver can verify private HR records, address custody records, delegation records, or policy histories unless those records are made available by local deployment or federation.

# Relationship to Exact Sender Binding

This document consumes exact sender binding results produced by senders or verifiers.  It does not redefine OpenPGP/MIME signing, key-to-sender resolution, or fail-closed sender alignment.  Those rules belong to `draft-hunn-openpgp-exact-sender-signatures`.  This document describes how local systems preserve and use the resulting identity, policy, and audit state over time.

# Temporal Identity State

A Sender Identity is more stable than any particular email address, display name, role, domain, organization, membership state, or key custody arrangement.  Exact sender binding therefore needs temporal identity state: records that say which attributes and authorities were valid for an identity at the message's send time.

A conforming system MUST evaluate identity, address, key, delegation, role, authority, and policy state as of the message's send time.  Current control of an address, domain, role, or key MUST NOT be used to reinterpret historical messages.

A conforming system SHOULD record time-bounded state for identity attributes that affect sending authority, search, audit, or forensic export.  Such records SHOULD include the Sender Identity identifier, effective start time, effective end time when no longer active, policy version, authority source, reason for change when available, and revocation or disabled state when applicable.

The following identity-state classes are commonly relevant:

* Address and display-name history: email address, display name, address state, and whether the address is active, alias, retired, blocked, transferred, or quarantined.
* Organization and domain history: tenant, organization, administrative realm, and authorized domains.
* Role and authority history: role name, authority class, approval scope, and authorized message categories such as invoices, password resets, legal notices, security alerts, administrator approvals, customer support replies, or automated notifications.
* Employment and membership lifecycle: invited, active, suspended, terminated, alumni, contractor, guest, or service-only state.
* Address custody and reassignment: former holder, later holder, transfer time, quarantine state, and policy version for addresses that move between Sender Identities.
* Identity merge and split history: source identities, resulting identities, effective time, approving authority, and handling of historical messages, active keys, addresses, delegations, and roles.
* Consent, preference, and name-display history: legal name, preferred name, display name, prior name, and audit-only name attributes where local policy records them.
* Key custody history: whether a Signing Key was held on a user device, server, hardware security module, webmail service, automation vault, or recovery environment, plus access-control, exportability, recovery, and escrow state when known.
* Binding confidence: provenance class for the identity binding, such as authoritative directory, HR or SCIM provisioning, administrator assertion, verified recovery, self-claimed identity, imported legacy data, manual contact confirmation, or unaudited migration.

A conforming system MUST treat address reuse as security-sensitive.  If an address is transferred from one Sender Identity to another, historical messages from the former identity remain bound to the former identity when valid at send time, and new messages from the later identity require a new exact sender binding for the later identity.  Search, display, audit, and forensic export MUST NOT merge identities merely because they used the same address at different times.

A retired address SHOULD fail exact sender binding for newly sent mail unless local policy explicitly keeps it as an active alias for the Sender Identity.  A blocked or quarantined address MUST fail exact sender binding for newly sent mail.

A conforming system MUST NOT merge Sender Identities merely because they share a display name, legal name, preferred name, mailbox local-part, or previously reused address.  User interfaces SHOULD show enough non-sensitive context to avoid misleading the user when two identities have the same or similar labels.

A conforming system MUST NOT allow a past role, expired authority scope, disabled membership state, revoked delegation, or low-confidence imported binding to authorize new mail when local policy requires stronger current proof.  Historical mail SHOULD remain auditable under the identity state that admitted it at send time.

User-facing interfaces SHOULD respect current display preferences where possible.  Audit and forensic systems MAY retain prior names when needed to explain historical messages, but such retention SHOULD follow local privacy policy and SHOULD avoid exposing prior personal names where a stable Sender Identity identifier is sufficient.

# Search and Audit Indexing

Systems that enforce exact sender binding can use the binding result as a stronger search and audit primitive than display names or RFC 5322 address text alone.  A conforming system MAY index messages by the resolved Sender Identity, Signing Key fingerprint, Delegation Record, Identity Class, and verification result.

Implementations SHOULD NOT expose a raw OpenPGP fingerprint or certificate hash as the only user-facing search handle.  Raw fingerprints are useful audit anchors, but they can leak correlation information, confuse users during key rotation, and fail to group multiple active keys that intentionally belong to one Sender Identity.

A sender or archive system SHOULD maintain a stable local Sender Identity identifier for search and audit.  Where privacy-preserving lookup tokens are needed, an implementation MAY derive an internal search token from local secret material and exact sender binding fields.  HMAC {{RFC2104}} with SHA-256 is one possible construction, for example:

```
search_token = HMAC-SHA256(local_secret, structured_encode(sender_identity_id, signing_fingerprint, policy_version))
```

The exact construction is local policy.  A conforming implementation that derives such tokens MUST use deterministic, unambiguous input encoding, such as a structured serialization or length-prefixed fields.  It MUST protect the local secret and MUST treat token regeneration, backup, and rotation as audit-sensitive operations.

Search and audit indexes SHOULD support at least the following queries when the underlying data is available:

* all messages from a resolved Sender Identity;
* all messages signed by a specific Signing Key fingerprint;
* all messages sent through a specific Delegation Record;
* all messages from an Identity Class, such as service or role mailbox;
* all messages claiming an address but failing exact sender binding;
* all messages with downgraded, unsigned, ambiguous, revoked, expired, or mismatched signing state.

# Impersonation and Downgrade Detection

Exact sender binding enables receivers and archives to distinguish messages that merely claim an address from messages that are cryptographically bound to the configured Sender Identity for that address.

A conforming verifier SHOULD flag a message as a possible impersonation when the message asserts a From or Sender address associated with a known Sender Identity but any of the following are true:

* no OpenPGP/MIME signature is present;
* the OpenPGP/MIME signature is invalid;
* the signing key is unmapped;
* the signing key maps to a different Sender Identity;
* the signing key is revoked, expired, disabled, or ambiguous;
* a required Delegation Record is missing, expired, revoked, or outside scope;
* the message is DKIM-authenticated but lacks exact sender binding.

A conforming verifier SHOULD track downgrade events when a Sender Identity that previously sent exact-sender-bound mail later sends mail that is unsigned, DKIM-only, signature-valid-but-unbound, or otherwise weaker than the prior exact sender state.

Downgrade detection is advisory unless local policy requires rejection.  A downgraded message MUST NOT be displayed, searched, archived, or exported as exact-sender-bound.

# Identity Timeline and Key Rotation Continuity

A conforming archive or audit system SHOULD maintain an identity timeline for each Sender Identity.  The timeline records the effective periods for Signing Keys, policy versions, Delegation Records, revocation state, disabled state, and verification results.

The identity timeline SHOULD support audit questions such as:

* which Signing Key was valid for a Sender Identity at the time a message was sent;
* when a key was created, rotated, expired, revoked, or disabled;
* which policy version admitted a message;
* when delegated sending authority existed;
* when downgrade, ambiguity, or impersonation events began;
* whether historical mail remains valid under the policy that existed at send time.

Key rotation MUST preserve continuity of the Sender Identity.  A new key replacing an old key MUST NOT cause historical messages to become unsearchable by Sender Identity, and an old key MUST NOT remain authorized beyond its recorded lifetime unless local policy explicitly extends it.

A conforming system SHOULD distinguish between:

* historical validity under the policy and key state at send time;
* current validity under present key and identity state;
* current trust decisions for replying, forwarding, displaying, or reusing the Sender Identity.

# Forensic Evidence Export

A conforming sender, receiver, or archive system SHOULD be able to export a forensic evidence bundle for a message when local policy permits disclosure.  The bundle gives auditors and incident responders enough material to reproduce or review the exact sender decision without relying on a user-interface label.

A forensic evidence bundle SHOULD include:

* the original message or preserved signed MIME entity;
* the OpenPGP/MIME signature material;
* the Signing Key fingerprint;
* discovered or locally configured public key material, when policy permits;
* the resolved Sender Identity identifier;
* the Sender Identity class;
* From and Sender fields;
* Message-ID and Date;
* Delegation Record, when used;
* policy version;
* verification result;
* failure state, when verification failed;
* audit timestamp and verifier identity;
* relevant identity timeline entries;
* downgrade or impersonation flags, when present.

Forensic export MUST NOT silently rewrite evidence into a cleaner form.  If the message was malformed, partially unverifiable, downgraded, ambiguous, or policy-dependent, the export MUST preserve and label that state.

Forensic export SHOULD avoid exposing unnecessary private metadata.  Implementations SHOULD provide redaction controls, but redaction MUST be visible in the exported evidence bundle.

# Security Considerations

Operational identity history is powerful and sensitive.  It can reveal stable identifiers, prior names, address changes, role history, delegation relationships, key custody, and internal policy state.  Implementations need access control, retention limits, tamper-evident logging, and clear operator visibility for export or redaction.

Search tokens derived with HMAC {{RFC2104}} are only as private as the local secret and the input discipline.  Implementations that derive tokens MUST use deterministic, unambiguous input encoding and MUST treat token regeneration, backup, and rotation as audit-sensitive operations.

A system MUST NOT use current identity state to rewrite historical sender decisions.  Historical mail needs to remain explainable under the policy and identity state in force at send time.

# Privacy Considerations

Operational identity history can expose prior names, employment status, role changes, delegation relationships, and address reuse.  User-facing systems SHOULD respect current display preferences where possible.  Audit systems MAY retain prior values when needed to explain historical messages, but retention and export SHOULD follow local privacy policy and SHOULD visibly mark redactions.

# IANA Considerations

This document has no IANA actions.

--- back

# Acknowledgements

This draft was motivated by operational requirements from GopherMailForge and by the need to distinguish stable identity history from mutable email addresses and display names.
