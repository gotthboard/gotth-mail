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

var upgradeMigrations = []Migration{
	newMigration(notificationDeliveryEvidenceMigrationVersion, notificationDeliveryEvidenceMigrationSQL),
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
