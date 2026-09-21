DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM role_bindings
        WHERE (role = 'global_admin' AND domain_id IS NOT NULL)
           OR (role IN ('domain_manager', 'scoped_domain_access') AND domain_id IS NULL)
    ) THEN
        RAISE EXCEPTION 'role_bindings contain inconsistent role/domain authority';
    END IF;
    IF EXISTS (
        SELECT identity_ref_id, role, domain_id
        FROM role_bindings
        GROUP BY identity_ref_id, role, domain_id
        HAVING count(*) > 1
    ) THEN
        RAISE EXCEPTION 'role_bindings contain duplicate scoped authority';
    END IF;
    IF EXISTS (
        SELECT identity_ref_id, role
        FROM role_bindings
        WHERE domain_id IS NULL
        GROUP BY identity_ref_id, role
        HAVING count(*) > 1
    ) THEN
        RAISE EXCEPTION 'role_bindings contain duplicate global authority';
    END IF;
END $$;

ALTER TABLE role_bindings
    ADD CONSTRAINT role_bindings_domain_authority_check CHECK (
        (role = 'global_admin' AND domain_id IS NULL)
        OR
        (role IN ('domain_manager', 'scoped_domain_access') AND domain_id IS NOT NULL)
    );

CREATE UNIQUE INDEX role_bindings_global_authority_unique
    ON role_bindings (identity_ref_id, role)
    WHERE domain_id IS NULL;

CREATE UNIQUE INDEX role_bindings_scoped_authority_unique
    ON role_bindings (identity_ref_id, role, domain_id)
    WHERE domain_id IS NOT NULL;
