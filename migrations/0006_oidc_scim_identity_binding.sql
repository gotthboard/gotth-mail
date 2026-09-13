DELETE FROM sessions;

DELETE FROM role_bindings
WHERE identity_ref_id IN (
    SELECT id FROM identity_refs WHERE provider = 'authentik'
);

DELETE FROM identity_refs WHERE provider = 'authentik';

ALTER TABLE identity_refs
    ADD COLUMN issuer text;

UPDATE identity_refs
SET issuer = 'local'
WHERE provider = 'local';

ALTER TABLE identity_refs
    ALTER COLUMN issuer SET NOT NULL,
    DROP CONSTRAINT identity_refs_provider_subject_key,
    ADD CONSTRAINT identity_refs_provider_issuer_subject_key
        UNIQUE (provider, issuer, subject),
    ADD CONSTRAINT identity_refs_issuer_size
        CHECK (length(issuer) BETWEEN 1 AND 2048),
    ADD CONSTRAINT identity_refs_subject_size
        CHECK (length(subject) BETWEEN 1 AND 1024);

CREATE UNIQUE INDEX identity_refs_authentik_mailbox_unique
    ON identity_refs (provider, mailbox_id)
    WHERE provider = 'authentik' AND mailbox_id IS NOT NULL;

ALTER TABLE sessions
    ALTER COLUMN identity_ref_id TYPE uuid USING identity_ref_id::uuid,
    ADD CONSTRAINT sessions_identity_ref_id_fkey
        FOREIGN KEY (identity_ref_id) REFERENCES identity_refs(id) ON DELETE CASCADE;

CREATE INDEX sessions_identity_ref_id_idx ON sessions (identity_ref_id);

UPDATE role_bindings
SET role = 'scoped_domain_access'
WHERE role = 'scoped_domain_admin';

ALTER TABLE role_bindings
    DROP CONSTRAINT role_bindings_role_check,
    ADD CONSTRAINT role_bindings_role_check
        CHECK (role IN ('global_admin', 'domain_manager', 'scoped_domain_access'));
