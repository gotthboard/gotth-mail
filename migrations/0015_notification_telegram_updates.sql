CREATE TABLE notification_telegram_updates (
    update_id bigint PRIMARY KEY,
    reply_json text NOT NULL,
    denied boolean NOT NULL,
    processed_at timestamp NOT NULL
);
