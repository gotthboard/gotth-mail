ALTER TABLE domains
    ADD COLUMN outbound_scope text NOT NULL DEFAULT 'unrestricted',
    ADD COLUMN outbound_policy_revision bigint NOT NULL DEFAULT 1,
    ADD CONSTRAINT domains_outbound_scope_check
        CHECK (outbound_scope IN ('unrestricted', 'same_domain_only')),
    ADD CONSTRAINT domains_outbound_policy_revision_check
        CHECK (outbound_policy_revision > 0);
