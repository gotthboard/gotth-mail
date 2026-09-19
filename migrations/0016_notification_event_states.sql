CREATE TABLE notification_event_states (
    event_key text PRIMARY KEY,
    state_hash text NOT NULL,
    sequence bigint NOT NULL,
    pending_alert_id text NULL,
    updated_at timestamp NOT NULL,
    CHECK (length(event_key) BETWEEN 1 AND 200),
    CHECK (state_hash ~ '^[0-9a-f]{64}$'),
    CHECK (sequence > 0),
    CHECK (pending_alert_id IS NULL OR pending_alert_id ~ '^event-[0-9a-f]{24}-[0-9]+$')
);
