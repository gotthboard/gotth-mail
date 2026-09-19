ALTER TABLE notification_approvals
    ADD COLUMN execution_started_at timestamp NULL,
    ADD COLUMN execution_attempts integer NOT NULL DEFAULT 0,
    ADD COLUMN execution_error_code text NULL,
    ADD CONSTRAINT notification_approvals_execution_attempts_nonnegative CHECK (execution_attempts >= 0),
    ADD CONSTRAINT notification_approvals_execution_error_code_safe CHECK (
        execution_error_code IS NULL OR execution_error_code ~ '^[a-z0-9_]{1,80}$'
    );
