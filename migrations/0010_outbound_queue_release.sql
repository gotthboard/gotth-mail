ALTER TABLE outbound_queue_messages
    DROP CONSTRAINT outbound_queue_messages_hold_state_check,
    ADD CONSTRAINT outbound_queue_messages_hold_state_check
        CHECK (hold_state IN (
            'pending',
            'hold_required',
            'reconciling',
            'held',
            'reconciliation_error',
            'release_reconciling',
            'release_error',
            'released'
        ));
