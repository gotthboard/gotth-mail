ALTER TABLE webmail_drafts
    ADD COLUMN cc_json text NOT NULL DEFAULT '[]',
    ADD COLUMN bcc_json text NOT NULL DEFAULT '[]';
