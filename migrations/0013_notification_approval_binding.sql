ALTER TABLE notification_approvals
    ADD COLUMN confirmation_binding_hash text NOT NULL DEFAULT '0000000000000000000000000000000000000000000000000000000000000000';

UPDATE notification_approvals
SET result = 'rejected', updated_at = CURRENT_TIMESTAMP
WHERE result = 'pending';

ALTER TABLE notification_approvals
    ALTER COLUMN confirmation_binding_hash DROP DEFAULT,
    ADD CONSTRAINT notification_approvals_binding_hash_required
        CHECK (confirmation_binding_hash ~ '^[0-9a-f]{64}$');
