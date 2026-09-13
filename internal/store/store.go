package store

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"time"
)

type Migration struct {
	Version, SQL, Checksum string
	AppliedAt              time.Time
	Dirty                  bool
}
type Runner struct{ Applied []Migration }

var InitialSchema = []string{
	`CREATE TABLE schema_migrations (version text primary key, applied_at timestamp not null, checksum text not null, dirty boolean not null default false);`,
	`CREATE TABLE domains (id uuid primary key, name text not null unique, enabled boolean not null default true, created_at timestamp not null, updated_at timestamp not null);`,
	`CREATE TABLE mailboxes (id uuid primary key, domain_id uuid not null references domains(id), local_part text not null, display_name text, enabled boolean not null default true, verifier text null, quota_bytes bigint null, created_at timestamp not null, updated_at timestamp not null, unique(domain_id, local_part));`,
	`CREATE TABLE aliases (id uuid primary key, domain_id uuid not null references domains(id), local_part text not null, targets_json text not null, enabled boolean not null default true, created_at timestamp not null, updated_at timestamp not null, unique(domain_id, local_part));`,
	`CREATE TABLE relays (id uuid primary key, domain_id uuid null references domains(id), name text not null, target text not null, enabled boolean not null default true, created_at timestamp not null, updated_at timestamp not null);`,
	`CREATE TABLE tokens (id uuid primary key, subject_type text not null, subject_id text not null, kind text not null check (kind in ('api','app_password','plugin_service','scim_client','break_glass')), verifier text not null, label text not null, scope_json text not null, created_at timestamp not null, last_used_at timestamp null, revoked_at timestamp null);`,
	`CREATE TABLE oidc_login_states (state_id text primary key, nonce text not null, browser_binding_hash text not null, redirect_after_login text not null, created_at timestamp not null, expires_at timestamp not null, used_at timestamp null);`,
	`CREATE TABLE sessions (id text primary key, identity_ref_id text not null, csrf_secret_hash text not null, auth_method text not null, created_at timestamp not null, expires_at timestamp not null, last_seen_at timestamp not null, revoked_at timestamp null);`,
	`CREATE TABLE identity_refs (id uuid primary key, provider text not null check (provider in ('authentik','local')), subject text not null, mailbox_id uuid null references mailboxes(id), created_at timestamp not null, updated_at timestamp not null, unique(provider, subject));`,
	`CREATE TABLE role_bindings (id uuid primary key, identity_ref_id uuid not null references identity_refs(id), role text not null check (role in ('global_admin','domain_manager','scoped_domain_admin')), domain_id uuid null references domains(id), created_at timestamp not null, updated_at timestamp not null);`,
	`CREATE TABLE audit_events (id uuid primary key, timestamp timestamp not null, actor_type text not null, actor_id text not null, source_ip text null, source_user_agent text null, action text not null, resource_type text not null, resource_id text not null, before_redacted_json text null, after_redacted_json text null, correlation_id text not null, result text not null check (result in ('success','failure','denied')), error_code text null);`,
	`CREATE TABLE generated_config_sets (id uuid primary key, status text not null check (status in ('staged','applied','superseded','failed')), input_config_hash text not null, db_state_hash text not null, deployment_policy_hash text not null, output_path text not null, diff_summary_json text null, created_by_actor text not null, created_at timestamp not null, applied_at timestamp null);`,
	`CREATE TABLE backup_artifacts (id uuid primary key, artifact_ref text not null unique, plugin_id text not null, schema_version text not null, config_set_id text not null, captured_at timestamp not null);`,
	`CREATE TABLE backup_verifications (id uuid primary key, artifact_id uuid not null references backup_artifacts(id), status text not null check (status in ('verify_running','verified','failed')), isolated_restore_ref text not null, failure_report_json text null, verified_at timestamp null, created_at timestamp not null);`,
	`CREATE TABLE snapshots (id uuid primary key, name text not null unique, generated_config_set_id uuid null references generated_config_sets(id), migration_version text not null, image_digest_json text not null, plugin_version_json text not null, deployment_policy_hash text not null, linked_backup_verification_id uuid null references backup_verifications(id), captured_at timestamp not null);`,
	`CREATE TABLE webmail_drafts (id text primary key, mailbox text not null, to_addr text not null, subject text not null, body_text text not null, signing_fingerprint text not null, state text not null check (state in ('draft','queued_for_submission','submitted','sent','failed')), reply_to text not null default '', forward_of text not null default '', attachments_json text not null default '[]', created_at timestamp not null, updated_at timestamp not null);`,
	`CREATE TABLE notification_deliveries (alert_id text primary key, alert_json text not null, status text not null check (status in ('pending','delivered','failed_retryable','failed_permanent')), reason text not null default '', created_at timestamp not null, updated_at timestamp not null);`,
	`CREATE TABLE notification_actor_mappings (transport text not null, external_actor_id text not null, actor_type text not null, actor_id text not null, scopes_json text not null default '[]', created_at timestamp not null, updated_at timestamp not null, primary key (transport, external_actor_id));`,
	`CREATE TABLE notification_approvals (id text primary key, transport text not null, external_actor_id text not null, actor_type text not null, actor_id text not null, action text not null, resource_type text not null, resource_id text not null, request_hash text not null, correlation_id text not null, expires_at timestamp not null, used_at timestamp null, result text not null default 'pending', created_at timestamp not null, updated_at timestamp not null);`,
	`CREATE TABLE plugin_registrations (id uuid primary key, name text not null unique, seam text not null check (seam in ('webmail','dns','acme','backup','notification','import')), image text not null, endpoint text not null, service_identity_token_id uuid references tokens(id), enabled boolean not null default true, created_at timestamp not null, updated_at timestamp not null, check (enabled = false or service_identity_token_id is not null));`,
}

const notificationDeliveryEvidenceMigrationVersion = "0002_notification_delivery_evidence"
const notificationDeliveryEvidenceMigrationSQL = `ALTER TABLE notification_deliveries
    ADD COLUMN evidence_json text NOT NULL DEFAULT '{}';`

const oidcProtectedAttemptsMigrationVersion = "0003_oidc_protected_attempts"
const oidcProtectedAttemptsMigrationSQL = `DELETE FROM oidc_login_states;

ALTER TABLE oidc_login_states
    DROP CONSTRAINT oidc_login_states_pkey,
    DROP COLUMN state_id,
    DROP COLUMN nonce,
    DROP COLUMN browser_binding_hash,
    ADD COLUMN state_hash bytea NOT NULL,
    ADD COLUMN nonce_ciphertext bytea NOT NULL,
    ADD COLUMN pkce_verifier_ciphertext bytea NOT NULL,
    ADD COLUMN context_ciphertext text NOT NULL,
    ADD COLUMN browser_binding_hash bytea NOT NULL,
    ADD CONSTRAINT oidc_login_states_pkey PRIMARY KEY (state_hash),
    ADD CONSTRAINT oidc_login_states_state_hash_size CHECK (octet_length(state_hash) = 32),
    ADD CONSTRAINT oidc_login_states_nonce_size CHECK (octet_length(nonce_ciphertext) = 72),
    ADD CONSTRAINT oidc_login_states_pkce_size CHECK (octet_length(pkce_verifier_ciphertext) = 72),
    ADD CONSTRAINT oidc_login_states_context_size CHECK (length(context_ciphertext) BETWEEN 1 AND 65536),
    ADD CONSTRAINT oidc_login_states_browser_hash_size CHECK (octet_length(browser_binding_hash) = 32),
    ADD CONSTRAINT oidc_login_states_redirect_size CHECK (length(redirect_after_login) BETWEEN 1 AND 2048),
    ADD CONSTRAINT oidc_login_states_expiry_order CHECK (expires_at > created_at),
    ADD CONSTRAINT oidc_login_states_use_order CHECK (used_at IS NULL OR used_at >= created_at);`

const scimResourcesMigrationVersion = "0004_scim_resources"
const scimResourcesMigrationSQL = `ALTER TABLE mailboxes
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
    WHERE external_id <> '';`

const appPasswordContractMigrationVersion = "0005_app_password_contract"
const appPasswordContractMigrationSQL = `ALTER TABLE tokens
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
    WHERE kind = 'app_password';`

const oidcSCIMIdentityBindingMigrationVersion = "0006_oidc_scim_identity_binding"
const oidcSCIMIdentityBindingMigrationSQL = `DELETE FROM sessions;

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
        CHECK (role IN ('global_admin', 'domain_manager', 'scoped_domain_access'));`

const scimGroupMembersMigrationVersion = "0007_scim_group_members"
const scimGroupMembersMigrationSQL = `CREATE TABLE scim_group_members (
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
    ON scim_group_members (scope, user_id, group_id);`

var upgradeMigrations = []Migration{
	newMigration(notificationDeliveryEvidenceMigrationVersion, notificationDeliveryEvidenceMigrationSQL),
	newMigration(oidcProtectedAttemptsMigrationVersion, oidcProtectedAttemptsMigrationSQL),
	newMigration(scimResourcesMigrationVersion, scimResourcesMigrationSQL),
	newMigration(appPasswordContractMigrationVersion, appPasswordContractMigrationSQL),
	newMigration(oidcSCIMIdentityBindingMigrationVersion, oidcSCIMIdentityBindingMigrationSQL),
	newMigration(scimGroupMembersMigrationVersion, scimGroupMembersMigrationSQL),
}

func newMigration(version, sql string) Migration {
	sum := sha256.Sum256([]byte(sql))
	return Migration{Version: version, SQL: sql, Checksum: hex.EncodeToString(sum[:])}
}

func (r *Runner) MigrateEmpty() error {
	if len(r.Applied) != 0 {
		return errors.New("database not empty")
	}
	for i, sql := range InitialSchema {
		if !strings.HasPrefix(sql, "CREATE TABLE ") {
			return errors.New("migration is not schema creation")
		}
		sum := sha256.Sum256([]byte(sql))
		r.Applied = append(r.Applied, Migration{Version: strings.Split(strings.TrimPrefix(sql, "CREATE TABLE "), " ")[0], SQL: sql, Checksum: hex.EncodeToString(sum[:]), AppliedAt: time.Now().UTC()})
		if i == 0 && !strings.Contains(sql, "dirty boolean") {
			return errors.New("schema_migrations missing dirty")
		}
	}
	return nil
}
func ValidateDomainName(s string) bool {
	if s != strings.ToLower(s) || len(s) < 3 || strings.Contains(s, "..") || !strings.Contains(s, ".") {
		return false
	}
	for _, r := range s {
		if !(r == '.' || r == '-' || r >= 'a' && r <= 'z' || r >= '0' && r <= '9') {
			return false
		}
	}
	return true
}
func ValidateTokenKind(k string) bool {
	switch k {
	case "api", "app_password", "plugin_service", "scim_client", "break_glass":
		return true
	}
	return false
}
func ValidatePluginRegistration(enabled bool, tokenKind string) error {
	if enabled && tokenKind != "plugin_service" {
		return errors.New("enabled plugin registration requires plugin_service credentials")
	}
	return nil
}
