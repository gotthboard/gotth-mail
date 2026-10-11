ALTER TABLE role_bindings
    ADD COLUMN operator_owned boolean NOT NULL DEFAULT TRUE,
    ADD COLUMN authority_revision bigint NOT NULL DEFAULT 1 CHECK (authority_revision > 0);

CREATE TABLE identity_group_role_mappings (
    id uuid PRIMARY KEY,
    issuer text NOT NULL CHECK (length(issuer) BETWEEN 1 AND 2048),
    scope text NOT NULL CHECK (length(scope) BETWEEN 1 AND 1024),
    group_id text NOT NULL CHECK (length(group_id) BETWEEN 1 AND 1024),
    role text NOT NULL CHECK (role IN ('global_admin', 'domain_manager', 'scoped_domain_access')),
    domain_id uuid NULL REFERENCES domains(id),
    revision bigint NOT NULL DEFAULT 1 CHECK (revision > 0),
    enabled boolean NOT NULL DEFAULT TRUE,
    group_deleted boolean NOT NULL DEFAULT FALSE,
    created_at timestamp NOT NULL,
    updated_at timestamp NOT NULL,
    CHECK ((role = 'global_admin' AND domain_id IS NULL)
        OR (role IN ('domain_manager', 'scoped_domain_access') AND domain_id IS NOT NULL)),
    CHECK (NOT group_deleted OR NOT enabled)
);

CREATE UNIQUE INDEX identity_group_role_mappings_global_unique
    ON identity_group_role_mappings (issuer, scope, group_id, role)
    WHERE domain_id IS NULL;
CREATE UNIQUE INDEX identity_group_role_mappings_scoped_unique
    ON identity_group_role_mappings (issuer, scope, group_id, role, domain_id)
    WHERE domain_id IS NOT NULL;

CREATE TABLE role_binding_group_sources (
    binding_id uuid NOT NULL REFERENCES role_bindings(id) ON DELETE CASCADE,
    mapping_id uuid NOT NULL REFERENCES identity_group_role_mappings(id) ON DELETE RESTRICT,
    PRIMARY KEY (binding_id, mapping_id)
);
CREATE INDEX role_binding_group_sources_mapping_idx
    ON role_binding_group_sources (mapping_id, binding_id);
