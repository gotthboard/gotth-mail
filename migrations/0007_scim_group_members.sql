CREATE TABLE scim_group_members (
    scope text NOT NULL,
    group_resource_type text NOT NULL DEFAULT 'Group',
    group_id text NOT NULL,
    user_resource_type text NOT NULL DEFAULT 'User',
    user_id text NOT NULL,
    PRIMARY KEY (scope, group_id, user_id),
    FOREIGN KEY (scope, group_resource_type, group_id)
        REFERENCES scim_resources(scope, resource_type, id)
        ON DELETE CASCADE,
    FOREIGN KEY (scope, user_resource_type, user_id)
        REFERENCES scim_resources(scope, resource_type, id)
        ON DELETE RESTRICT,
    CHECK (group_resource_type = 'Group'),
    CHECK (user_resource_type = 'User'),
    CHECK (length(scope) BETWEEN 1 AND 1024),
    CHECK (length(group_id) BETWEEN 1 AND 1024),
    CHECK (length(user_id) BETWEEN 1 AND 1024),
    CHECK (group_id <> user_id)
);

CREATE INDEX scim_group_members_user_idx
    ON scim_group_members (scope, user_id, group_id);
