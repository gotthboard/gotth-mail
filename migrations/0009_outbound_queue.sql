CREATE TABLE outbound_queue_messages (
    queue_id text PRIMARY KEY,
    arrival_fingerprint text NOT NULL,
    envelope_sender text NOT NULL,
    recipient_set_digest text NOT NULL,
    source_set_digest text NOT NULL,
    hold_state text NOT NULL DEFAULT 'pending',
    policy_reason text NULL,
    policy_revisions_json jsonb NOT NULL DEFAULT '{}'::jsonb,
    reconciliation_attempts bigint NOT NULL DEFAULT 0,
    last_error_code text NULL,
    first_seen_at timestamp NOT NULL,
    updated_at timestamp NOT NULL,
    CHECK (length(queue_id) BETWEEN 12 AND 100),
    CHECK (queue_id ~ '^[0-9B-DF-HJ-NP-TV-Zb-df-hj-np-tv-z]{10,}z[0-9B-DF-HJ-NP-TV-Zb-df-hj-np-tv-z]+$'),
    CHECK (arrival_fingerprint ~ '^[0-9a-f]{64}$'),
    CHECK (length(envelope_sender) BETWEEN 2 AND 254 AND envelope_sender !~ '[[:cntrl:]]'),
    CHECK (recipient_set_digest ~ '^[0-9a-f]{64}$'),
    CHECK (source_set_digest ~ '^[0-9a-f]{64}$'),
    CHECK (hold_state IN ('pending', 'hold_required', 'reconciling', 'held', 'reconciliation_error', 'released')),
    CHECK (policy_reason IS NULL OR policy_reason IN ('recipient_domain_policy_hold', 'cross_domain_policy_conflict', 'outbound_policy_unavailable')),
    CHECK (reconciliation_attempts >= 0),
    CHECK (last_error_code IS NULL OR (length(last_error_code) BETWEEN 1 AND 128 AND last_error_code ~ '^[a-z0-9_]+$')),
    CHECK (updated_at >= first_seen_at)
);

CREATE TABLE outbound_queue_recipients (
    queue_id text NOT NULL REFERENCES outbound_queue_messages(queue_id) ON DELETE CASCADE,
    recipient text NOT NULL,
    recipient_domain text NOT NULL,
    PRIMARY KEY (queue_id, recipient),
    CHECK (length(recipient) BETWEEN 3 AND 254 AND recipient !~ '[[:cntrl:]]'),
    CHECK (length(recipient_domain) BETWEEN 1 AND 253),
    CHECK (recipient_domain = lower(recipient_domain) AND recipient_domain ~ '^[a-z0-9.-]+$')
);

CREATE INDEX outbound_queue_recipients_domain_idx
    ON outbound_queue_recipients (recipient_domain, queue_id);

CREATE TABLE outbound_system_senders (
    id text PRIMARY KEY,
    domain_id uuid NOT NULL REFERENCES domains(id) ON DELETE RESTRICT,
    address text NOT NULL UNIQUE,
    enabled boolean NOT NULL DEFAULT true,
    revision bigint NOT NULL DEFAULT 1,
    created_at timestamp NOT NULL,
    updated_at timestamp NOT NULL,
    CHECK (length(id) BETWEEN 1 AND 320 AND id !~ '[[:cntrl:]]' AND id = btrim(id)),
    CHECK (length(address) BETWEEN 3 AND 254 AND address !~ '[[:cntrl:]]'),
    CHECK (revision > 0),
    CHECK (updated_at >= created_at)
);

CREATE INDEX outbound_system_senders_domain_idx
    ON outbound_system_senders (domain_id, id);

CREATE TABLE outbound_queue_sources (
    queue_id text NOT NULL REFERENCES outbound_queue_messages(queue_id) ON DELETE CASCADE,
    source_kind text NOT NULL,
    object_id text NOT NULL,
    PRIMARY KEY (queue_id, source_kind, object_id),
    CHECK (source_kind IN ('authenticated_mailbox', 'envelope_sender', 'system_sender', 'alias', 'forward', 'list', 'catch_all')),
    CHECK (length(object_id) BETWEEN 1 AND 320 AND object_id !~ '[[:cntrl:]]' AND object_id = btrim(object_id))
);

CREATE INDEX outbound_queue_sources_object_idx
    ON outbound_queue_sources (source_kind, object_id, queue_id);
