ALTER TABLE mailboxes
    ADD COLUMN scim_resource_id text NULL;

CREATE UNIQUE INDEX mailboxes_scim_resource_id_unique
    ON mailboxes (scim_resource_id)
    WHERE scim_resource_id IS NOT NULL;

CREATE TABLE scim_resources (
    scope text NOT NULL,
    resource_type text NOT NULL,
    id text NOT NULL,
    external_id text NOT NULL DEFAULT '',
    manager text NOT NULL DEFAULT '',
    version text NOT NULL,
    credential_version text NOT NULL DEFAULT '',
    created_unix_nano bigint NOT NULL,
    last_modified_unix_nano bigint NOT NULL,
    data bytea NOT NULL,
    PRIMARY KEY (scope, resource_type, id),
    UNIQUE (id),
    CHECK (length(scope) BETWEEN 1 AND 1024),
    CHECK (length(resource_type) BETWEEN 1 AND 1024),
    CHECK (length(id) BETWEEN 1 AND 1024),
    CHECK (length(external_id) <= 65536),
    CHECK (length(manager) <= 1024),
    CHECK (length(version) BETWEEN 1 AND 1024),
    CHECK (length(credential_version) <= 1024),
    CHECK (last_modified_unix_nano >= created_unix_nano),
    CHECK (octet_length(data) BETWEEN 1 AND 1048576)
);

CREATE TABLE scim_index_contracts (
    scope text NOT NULL,
    resource_type text NOT NULL,
    name_folded text NOT NULL,
    case_exact boolean NOT NULL,
    unique_value boolean NOT NULL,
    PRIMARY KEY (scope, resource_type, name_folded)
);

CREATE TABLE scim_resource_indexes (
    scope text NOT NULL,
    resource_type text NOT NULL,
    resource_id text NOT NULL,
    name text NOT NULL,
    name_folded text NOT NULL,
    value text NOT NULL,
    ordinal integer NOT NULL,
    case_exact boolean NOT NULL,
    unique_value boolean NOT NULL,
    PRIMARY KEY (scope, resource_type, resource_id, name_folded),
    FOREIGN KEY (scope, resource_type, resource_id)
        REFERENCES scim_resources(scope, resource_type, id)
        ON DELETE CASCADE,
    CHECK (length(name) BETWEEN 1 AND 1024),
    CHECK (name_folded = lower(name)),
    CHECK (ordinal >= 0),
    CHECK (length(value) BETWEEN 1 AND 65536)
);

CREATE UNIQUE INDEX scim_resource_indexes_ci_unique
    ON scim_resource_indexes(scope, resource_type, name_folded, lower(value))
    WHERE unique_value AND NOT case_exact;

CREATE UNIQUE INDEX scim_resource_indexes_cs_unique
    ON scim_resource_indexes(scope, resource_type, name_folded, value)
    WHERE unique_value AND case_exact;

CREATE TABLE scim_tombstones (
    scope text NOT NULL,
    resource_type text NOT NULL,
    id text NOT NULL,
    external_id text NOT NULL DEFAULT '',
    manager text NOT NULL DEFAULT '',
    version text NOT NULL,
    deleted_unix_nano bigint NOT NULL,
    PRIMARY KEY (scope, resource_type, id),
    UNIQUE (id),
    CHECK (length(scope) BETWEEN 1 AND 1024),
    CHECK (length(resource_type) BETWEEN 1 AND 1024),
    CHECK (length(id) BETWEEN 1 AND 1024),
    CHECK (length(external_id) <= 65536),
    CHECK (length(manager) <= 1024),
    CHECK (length(version) BETWEEN 1 AND 1024)
);

CREATE UNIQUE INDEX scim_tombstones_external_id_unique
    ON scim_tombstones(scope, resource_type, external_id)
    WHERE external_id <> '';
