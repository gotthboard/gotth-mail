ALTER TABLE tokens
    ADD COLUMN public_id text NULL;

UPDATE tokens
SET public_id = label
WHERE kind = 'app_password';

ALTER TABLE tokens
    ADD CONSTRAINT tokens_app_password_public_id_contract CHECK (
        (kind = 'app_password'
            AND public_id IS NOT NULL
            AND length(public_id) BETWEEN 5 AND 128
            AND length(label) BETWEEN 1 AND 128)
        OR
        (kind <> 'app_password' AND public_id IS NULL)
    );

CREATE UNIQUE INDEX tokens_app_password_public_id_unique
    ON tokens (public_id)
    WHERE kind = 'app_password';
