ALTER TABLE webmail_drafts
    DROP CONSTRAINT webmail_drafts_state_check,
    ADD CONSTRAINT webmail_drafts_state_check
        CHECK (state IN ('draft','queued_for_submission','submitted','sent','failed','delivery_uncertain'));
