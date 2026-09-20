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

const outboundPolicyMigrationVersion = "0008_outbound_policy"
const outboundPolicyMigrationSQL = `ALTER TABLE domains
    ADD COLUMN outbound_scope text NOT NULL DEFAULT 'unrestricted',
    ADD COLUMN outbound_policy_revision bigint NOT NULL DEFAULT 1,
    ADD CONSTRAINT domains_outbound_scope_check
        CHECK (outbound_scope IN ('unrestricted', 'same_domain_only')),
    ADD CONSTRAINT domains_outbound_policy_revision_check
        CHECK (outbound_policy_revision > 0);`

const outboundQueueMigrationVersion = "0009_outbound_queue"
const outboundQueueMigrationSQL = `CREATE TABLE outbound_queue_messages (
    queue_id text PRIMARY KEY,
    arrival_fingerprint text NOT NULL,
    envelope_sender text NOT NULL,
    recipient_set_digest text NOT NULL,
    source_set_digest text NOT NULL,
    hold_state text NOT NULL DEFAULT 'pending',
    policy_reason text NULL,
    policy_revisions_json jsonb NOT NULL DEFAULT '{}'::jsonb,
    reconciliation_attempts bigint NOT NULL DEFAULT 0,
    last_error_code text NULL,
    first_seen_at timestamp NOT NULL,
    updated_at timestamp NOT NULL,
    CHECK (length(queue_id) BETWEEN 12 AND 100),
    CHECK (queue_id ~ '^[0-9B-DF-HJ-NP-TV-Zb-df-hj-np-tv-z]{10,}z[0-9B-DF-HJ-NP-TV-Zb-df-hj-np-tv-z]+$'),
    CHECK (arrival_fingerprint ~ '^[0-9a-f]{64}$'),
    CHECK (length(envelope_sender) BETWEEN 2 AND 254 AND envelope_sender !~ '[[:cntrl:]]'),
    CHECK (recipient_set_digest ~ '^[0-9a-f]{64}$'),
    CHECK (source_set_digest ~ '^[0-9a-f]{64}$'),
    CHECK (hold_state IN ('pending', 'hold_required', 'reconciling', 'held', 'reconciliation_error', 'released')),
    CHECK (policy_reason IS NULL OR policy_reason IN ('recipient_domain_policy_hold', 'cross_domain_policy_conflict', 'outbound_policy_unavailable')),
    CHECK (reconciliation_attempts >= 0),
    CHECK (last_error_code IS NULL OR (length(last_error_code) BETWEEN 1 AND 128 AND last_error_code ~ '^[a-z0-9_]+$')),
    CHECK (updated_at >= first_seen_at)
);

CREATE TABLE outbound_queue_recipients (
    queue_id text NOT NULL REFERENCES outbound_queue_messages(queue_id) ON DELETE CASCADE,
    recipient text NOT NULL,
    recipient_domain text NOT NULL,
    PRIMARY KEY (queue_id, recipient),
    CHECK (length(recipient) BETWEEN 3 AND 254 AND recipient !~ '[[:cntrl:]]'),
    CHECK (length(recipient_domain) BETWEEN 1 AND 253),
    CHECK (recipient_domain = lower(recipient_domain) AND recipient_domain ~ '^[a-z0-9.-]+$')
);

CREATE INDEX outbound_queue_recipients_domain_idx
    ON outbound_queue_recipients (recipient_domain, queue_id);

CREATE TABLE outbound_system_senders (
    id text PRIMARY KEY,
    domain_id uuid NOT NULL REFERENCES domains(id) ON DELETE RESTRICT,
    address text NOT NULL UNIQUE,
    enabled boolean NOT NULL DEFAULT true,
    revision bigint NOT NULL DEFAULT 1,
    created_at timestamp NOT NULL,
    updated_at timestamp NOT NULL,
    CHECK (length(id) BETWEEN 1 AND 320 AND id !~ '[[:cntrl:]]' AND id = btrim(id)),
    CHECK (length(address) BETWEEN 3 AND 254 AND address !~ '[[:cntrl:]]'),
    CHECK (revision > 0),
    CHECK (updated_at >= created_at)
);

CREATE INDEX outbound_system_senders_domain_idx
    ON outbound_system_senders (domain_id, id);

CREATE TABLE outbound_queue_sources (
    queue_id text NOT NULL REFERENCES outbound_queue_messages(queue_id) ON DELETE CASCADE,
    source_kind text NOT NULL,
    object_id text NOT NULL,
    PRIMARY KEY (queue_id, source_kind, object_id),
    CHECK (source_kind IN ('authenticated_mailbox', 'envelope_sender', 'system_sender', 'alias', 'forward', 'list', 'catch_all')),
    CHECK (length(object_id) BETWEEN 1 AND 320 AND object_id !~ '[[:cntrl:]]' AND object_id = btrim(object_id))
);

CREATE INDEX outbound_queue_sources_object_idx
    ON outbound_queue_sources (source_kind, object_id, queue_id);`

const outboundQueueReleaseMigrationVersion = "0010_outbound_queue_release"
const outboundQueueReleaseMigrationSQL = `ALTER TABLE outbound_queue_messages
    DROP CONSTRAINT outbound_queue_messages_hold_state_check,
    ADD CONSTRAINT outbound_queue_messages_hold_state_check
        CHECK (hold_state IN (
            'pending',
            'hold_required',
            'reconciling',
            'held',
            'reconciliation_error',
            'release_reconciling',
            'release_error',
            'released'
        ));`

const webmailCCBCCMigrationVersion = "0011_webmail_cc_bcc"
const webmailCCBCCMigrationSQL = `ALTER TABLE webmail_drafts
    ADD COLUMN cc_json text NOT NULL DEFAULT '[]',
    ADD COLUMN bcc_json text NOT NULL DEFAULT '[]';`

const webmailDeliveryUncertainMigrationVersion = "0012_webmail_delivery_uncertain"
const webmailDeliveryUncertainMigrationSQL = `ALTER TABLE webmail_drafts
    DROP CONSTRAINT webmail_drafts_state_check,
    ADD CONSTRAINT webmail_drafts_state_check
        CHECK (state IN ('draft','queued_for_submission','submitted','sent','failed','delivery_uncertain'));`

const notificationApprovalBindingMigrationVersion = "0013_notification_approval_binding"
const notificationApprovalBindingMigrationSQL = `ALTER TABLE notification_approvals
    ADD COLUMN confirmation_binding_hash text NOT NULL DEFAULT '0000000000000000000000000000000000000000000000000000000000000000';

UPDATE notification_approvals
SET result = 'rejected', updated_at = CURRENT_TIMESTAMP
WHERE result = 'pending';

ALTER TABLE notification_approvals
    ALTER COLUMN confirmation_binding_hash DROP DEFAULT,
    ADD CONSTRAINT notification_approvals_binding_hash_required
        CHECK (confirmation_binding_hash ~ '^[0-9a-f]{64}$');`

const notificationApprovalExecutionMigrationVersion = "0014_notification_approval_execution"
const notificationApprovalExecutionMigrationSQL = `ALTER TABLE notification_approvals
    ADD COLUMN execution_started_at timestamp NULL,
    ADD COLUMN execution_attempts integer NOT NULL DEFAULT 0,
    ADD COLUMN execution_error_code text NULL,
    ADD CONSTRAINT notification_approvals_execution_attempts_nonnegative CHECK (execution_attempts >= 0),
    ADD CONSTRAINT notification_approvals_execution_error_code_safe CHECK (
        execution_error_code IS NULL OR execution_error_code ~ '^[a-z0-9_]{1,80}$'
    );`

const notificationTelegramUpdatesMigrationVersion = "0015_notification_telegram_updates"
const notificationTelegramUpdatesMigrationSQL = `CREATE TABLE notification_telegram_updates (
    update_id bigint PRIMARY KEY,
    reply_json text NOT NULL,
    denied boolean NOT NULL,
    processed_at timestamp NOT NULL
);`

const notificationEventStatesMigrationVersion = "0016_notification_event_states"
const notificationEventStatesMigrationSQL = `CREATE TABLE notification_event_states (
    event_key text PRIMARY KEY,
    state_hash text NOT NULL,
    sequence bigint NOT NULL,
    pending_alert_id text NULL,
    updated_at timestamp NOT NULL,
    CHECK (length(event_key) BETWEEN 1 AND 200),
    CHECK (state_hash ~ '^[0-9a-f]{64}$'),
    CHECK (sequence > 0),
    CHECK (pending_alert_id IS NULL OR pending_alert_id ~ '^event-[0-9a-f]{24}-[0-9]+$')
);`

const extensionAdministratorMigrationVersion = "0017_extension_administrator"
const extensionAdministratorMigrationSQL = `CREATE TABLE extension_instances (
    instance_id uuid PRIMARY KEY,
    product text NOT NULL DEFAULT 'gotth-mail',
    extension_id text NOT NULL,
    repository text NOT NULL,
    artifact_pin text NOT NULL,
    previous_artifact_pin text NULL,
    previous_version_json jsonb NULL,
    available_update_pin text NULL,
    manifest_sha256 text NOT NULL,
    grant_sha256 text NOT NULL,
    session_sha256 text NOT NULL,
    capabilities_json jsonb NOT NULL DEFAULT '[]'::jsonb,
    interfaces_json jsonb NOT NULL DEFAULT '[]'::jsonb,
    secret_slots_json jsonb NOT NULL DEFAULT '[]'::jsonb,
    metadata_json jsonb NOT NULL,
    configuration_json jsonb NOT NULL DEFAULT '{}'::jsonb,
    configuration_revision bigint NOT NULL DEFAULT 1,
    lifecycle text NOT NULL DEFAULT 'discovered',
    health_code text NOT NULL DEFAULT 'extension.unknown',
    tested_revision bigint NULL,
    enabled boolean NOT NULL DEFAULT false,
    routed boolean NOT NULL DEFAULT false,
    last_correlation_id text NOT NULL DEFAULT '',
    created_at timestamp NOT NULL,
    updated_at timestamp NOT NULL,
    UNIQUE (product, extension_id),
    CHECK (product = 'gotth-mail'),
    CHECK (length(extension_id) BETWEEN 3 AND 128),
    CHECK (repository ~ '^https://github\.com/gotthboard/gotth-extension-[a-z0-9-]{1,63}$'),
    CHECK (artifact_pin ~ '^sha256:[0-9a-f]{64}$'),
    CHECK ((previous_artifact_pin IS NULL) = (previous_version_json IS NULL)),
    CHECK (previous_artifact_pin IS NULL OR previous_artifact_pin ~ '^sha256:[0-9a-f]{64}$'),
    CHECK (available_update_pin IS NULL OR available_update_pin ~ '^sha256:[0-9a-f]{64}$'),
    CHECK (manifest_sha256 ~ '^[0-9a-f]{64}$'),
    CHECK (grant_sha256 ~ '^[0-9a-f]{64}$'),
    CHECK (session_sha256 ~ '^[0-9a-f]{64}$'),
    CHECK (configuration_revision > 0),
    CHECK (tested_revision IS NULL OR tested_revision > 0),
    CHECK (lifecycle IN ('discovered','starting','ready','degraded','stopping','stopped','failed')),
    CHECK (health_code ~ '^[a-z][a-z0-9-]*(\.[a-z][a-z0-9-]*)+$'),
    CHECK (NOT routed OR enabled),
    CHECK (updated_at >= created_at)
);

CREATE TABLE extension_secrets (
    instance_id uuid NOT NULL REFERENCES extension_instances(instance_id) ON DELETE CASCADE,
    slot text NOT NULL,
    nonce bytea NOT NULL,
    ciphertext bytea NOT NULL,
    key_version integer NOT NULL DEFAULT 1,
    configured_at timestamp NOT NULL,
    rotated_at timestamp NOT NULL,
    PRIMARY KEY (instance_id, slot),
    CHECK (length(slot) BETWEEN 3 AND 128),
    CHECK (octet_length(nonce) = 12),
    CHECK (octet_length(ciphertext) BETWEEN 17 AND 4112),
    CHECK (key_version > 0),
    CHECK (rotated_at >= configured_at)
);

CREATE TABLE extension_operation_previews (
    id text PRIMARY KEY,
    instance_id uuid NOT NULL REFERENCES extension_instances(instance_id) ON DELETE CASCADE,
    operation text NOT NULL,
    actor_type text NOT NULL,
    actor_id text NOT NULL,
    base_revision bigint NOT NULL,
    payload_json jsonb NOT NULL,
    payload_sha256 text NOT NULL,
    secret_binding_sha256 text NOT NULL,
    confirmation_sha256 text NOT NULL,
    privilege_diff_json jsonb NOT NULL DEFAULT '[]'::jsonb,
    configuration_diff_json jsonb NOT NULL DEFAULT '[]'::jsonb,
    secret_slot_diff_json jsonb NOT NULL DEFAULT '[]'::jsonb,
    created_at timestamp NOT NULL,
    expires_at timestamp NOT NULL,
    consumed_at timestamp NULL,
    CHECK (id ~ '^extp_[0-9a-f]{24}$'),
    CHECK (operation IN ('configure','update','delete_secrets','uninstall')),
    CHECK (length(actor_type) BETWEEN 1 AND 64),
    CHECK (length(actor_id) BETWEEN 1 AND 1024),
    CHECK (base_revision > 0),
    CHECK (payload_sha256 ~ '^[0-9a-f]{64}$'),
    CHECK (secret_binding_sha256 ~ '^[0-9a-f]{64}$'),
    CHECK (confirmation_sha256 ~ '^[0-9a-f]{64}$'),
    CHECK (expires_at > created_at),
    CHECK (consumed_at IS NULL OR consumed_at >= created_at)
);

CREATE INDEX extension_instances_state_idx
    ON extension_instances (enabled, lifecycle, extension_id);

CREATE INDEX extension_operation_previews_instance_idx
    ON extension_operation_previews (instance_id, operation, expires_at)
    WHERE consumed_at IS NULL;`

var upgradeMigrations = []Migration{
	newMigration(notificationDeliveryEvidenceMigrationVersion, notificationDeliveryEvidenceMigrationSQL),
	newMigration(oidcProtectedAttemptsMigrationVersion, oidcProtectedAttemptsMigrationSQL),
	newMigration(scimResourcesMigrationVersion, scimResourcesMigrationSQL),
	newMigration(appPasswordContractMigrationVersion, appPasswordContractMigrationSQL),
	newMigration(oidcSCIMIdentityBindingMigrationVersion, oidcSCIMIdentityBindingMigrationSQL),
	newMigration(scimGroupMembersMigrationVersion, scimGroupMembersMigrationSQL),
	newMigration(outboundPolicyMigrationVersion, outboundPolicyMigrationSQL),
	newMigration(outboundQueueMigrationVersion, outboundQueueMigrationSQL),
	newMigration(outboundQueueReleaseMigrationVersion, outboundQueueReleaseMigrationSQL),
	newMigration(webmailCCBCCMigrationVersion, webmailCCBCCMigrationSQL),
	newMigration(webmailDeliveryUncertainMigrationVersion, webmailDeliveryUncertainMigrationSQL),
	newMigration(notificationApprovalBindingMigrationVersion, notificationApprovalBindingMigrationSQL),
	newMigration(notificationApprovalExecutionMigrationVersion, notificationApprovalExecutionMigrationSQL),
	newMigration(notificationTelegramUpdatesMigrationVersion, notificationTelegramUpdatesMigrationSQL),
	newMigration(notificationEventStatesMigrationVersion, notificationEventStatesMigrationSQL),
	newMigration(extensionAdministratorMigrationVersion, extensionAdministratorMigrationSQL),
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
