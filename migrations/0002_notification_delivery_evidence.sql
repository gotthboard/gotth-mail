ALTER TABLE notification_deliveries
    ADD COLUMN evidence_json text NOT NULL DEFAULT '{}';
