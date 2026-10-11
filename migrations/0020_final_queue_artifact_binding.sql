CREATE TABLE final_queue_artifacts (
    artifact_id text PRIMARY KEY,
    signed_message_id text NOT NULL UNIQUE,
    signed_date timestamp(6) NOT NULL,
    content_sha256 text NOT NULL,
    content_bytes bigint NOT NULL,
    local_identity_id text NOT NULL,
    local_mailbox_id uuid NOT NULL REFERENCES mailboxes(id) ON DELETE RESTRICT,
    envelope_sender text NOT NULL,
    null_envelope_sender boolean NOT NULL,
    signer_identity_id text NOT NULL,
    signer_fingerprint text NOT NULL,
    source_set_digest text NOT NULL,
    recipient_set_digest text NOT NULL,
    provenance_digest text NOT NULL,
    state text NOT NULL DEFAULT 'prepared',
    prepared_at timestamp(6) NOT NULL,
    updated_at timestamp(6) NOT NULL,
    expires_at timestamp(6) NOT NULL,
    CHECK (length(artifact_id) BETWEEN 1 AND 128 AND artifact_id !~ '[[:cntrl:]]' AND artifact_id = btrim(artifact_id)),
    CHECK (length(signed_message_id) BETWEEN 3 AND 255 AND signed_message_id !~ '[[:cntrl:]]' AND left(signed_message_id, 1) = '<' AND right(signed_message_id, 1) = '>'),
    CHECK (content_sha256 ~ '^[0-9a-f]{64}$'),
    CHECK (content_bytes BETWEEN 1 AND 72796392),
    CHECK (length(local_identity_id) BETWEEN 1 AND 320 AND local_identity_id !~ '[[:cntrl:]]' AND local_identity_id = btrim(local_identity_id)),
    CHECK ((null_envelope_sender AND envelope_sender = '<>') OR (NOT null_envelope_sender AND envelope_sender <> '<>')),
    CHECK (length(envelope_sender) BETWEEN 2 AND 254 AND envelope_sender !~ '[[:cntrl:]]' AND envelope_sender = btrim(envelope_sender)),
    CHECK (length(signer_identity_id) BETWEEN 1 AND 320 AND signer_identity_id !~ '[[:cntrl:]]' AND signer_identity_id = btrim(signer_identity_id)),
    CHECK (signer_fingerprint ~ '^([0-9a-f]{40}|[0-9a-f]{64})$'),
    CHECK (source_set_digest ~ '^[0-9a-f]{64}$'),
    CHECK (recipient_set_digest ~ '^[0-9a-f]{64}$'),
    CHECK (provenance_digest ~ '^[0-9a-f]{64}$'),
    CHECK (state IN ('prepared', 'bound')),
    CHECK (updated_at >= prepared_at),
    CHECK (expires_at > prepared_at)
);

CREATE TABLE final_queue_recipients (
    artifact_id text NOT NULL REFERENCES final_queue_artifacts(artifact_id) ON DELETE CASCADE,
    recipient text NOT NULL,
    recipient_domain text NOT NULL,
    ordinal integer NOT NULL,
    PRIMARY KEY (artifact_id, recipient),
    UNIQUE (artifact_id, ordinal),
    CHECK (length(recipient) BETWEEN 3 AND 254 AND recipient !~ '[[:cntrl:]]' AND recipient = btrim(recipient)),
    CHECK (length(recipient_domain) BETWEEN 1 AND 253 AND recipient_domain = lower(recipient_domain) AND recipient_domain ~ '^[a-z0-9.-]+$'),
    CHECK (ordinal >= 0)
);

CREATE TABLE final_queue_sources (
    artifact_id text NOT NULL REFERENCES final_queue_artifacts(artifact_id) ON DELETE CASCADE,
    source_kind text NOT NULL,
    object_id text NOT NULL,
    revision bigint NOT NULL,
    ordinal integer NOT NULL,
    PRIMARY KEY (artifact_id, source_kind, object_id),
    UNIQUE (artifact_id, ordinal),
    CHECK (source_kind IN ('authenticated_mailbox', 'envelope_sender', 'system_sender', 'alias', 'forward', 'list', 'catch_all')),
    CHECK (length(object_id) BETWEEN 1 AND 320 AND object_id !~ '[[:cntrl:]]' AND object_id = btrim(object_id)),
    CHECK (revision > 0),
    CHECK (ordinal >= 0)
);

CREATE TABLE final_queue_bindings (
    instance_id text NOT NULL,
    queue_id text NOT NULL REFERENCES outbound_queue_messages(queue_id) ON DELETE RESTRICT,
    artifact_id text NOT NULL REFERENCES final_queue_artifacts(artifact_id) ON DELETE RESTRICT,
    arrival_fingerprint text NOT NULL,
    bound_at timestamp(6) NOT NULL,
    PRIMARY KEY (instance_id, queue_id),
    UNIQUE (queue_id),
    UNIQUE (artifact_id),
    CHECK (length(instance_id) BETWEEN 1 AND 128 AND instance_id !~ '[[:cntrl:]]' AND instance_id = btrim(instance_id)),
    CHECK (length(queue_id) BETWEEN 12 AND 100),
    CHECK (queue_id ~ '^[0-9B-DF-HJ-NP-TV-Zb-df-hj-np-tv-z]{10,}z[0-9B-DF-HJ-NP-TV-Zb-df-hj-np-tv-z]+$'),
    CHECK (arrival_fingerprint ~ '^[0-9a-f]{64}$')
);

