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
	`CREATE TABLE mailboxes (id uuid primary key, domain_id uuid not null references domains(id), local_part text not null, display_name text, enabled boolean not null default true, quota_bytes bigint null, created_at timestamp not null, updated_at timestamp not null, unique(domain_id, local_part));`,
	`CREATE TABLE aliases (id uuid primary key, domain_id uuid not null references domains(id), local_part text not null, targets_json text not null, enabled boolean not null default true, created_at timestamp not null, updated_at timestamp not null, unique(domain_id, local_part));`,
	`CREATE TABLE relays (id uuid primary key, domain_id uuid null references domains(id), name text not null, target text not null, enabled boolean not null default true, created_at timestamp not null, updated_at timestamp not null);`,
	`CREATE TABLE tokens (id uuid primary key, subject_type text not null, subject_id text not null, kind text not null, verifier text not null, label text not null, scope_json text not null, created_at timestamp not null, last_used_at timestamp null, revoked_at timestamp null);`,
	`CREATE TABLE identity_refs (id uuid primary key, provider text not null, subject text not null, mailbox_id uuid null references mailboxes(id), created_at timestamp not null, updated_at timestamp not null, unique(provider, subject));`,
	`CREATE TABLE role_bindings (id uuid primary key, identity_ref_id uuid not null references identity_refs(id), role text not null, domain_id uuid null references domains(id), created_at timestamp not null, updated_at timestamp not null);`,
	`CREATE TABLE audit_events (id uuid primary key, timestamp timestamp not null, actor_type text not null, actor_id text not null, action text not null, resource_type text not null, resource_id text not null, before_redacted_json text null, after_redacted_json text null, correlation_id text not null, result text not null, error_code text null);`,
	`CREATE TABLE generated_config_sets (id uuid primary key, status text not null, input_config_hash text not null, db_state_hash text not null, deployment_policy_hash text not null, output_path text not null, diff_summary_json text null, created_by_actor text not null, created_at timestamp not null, applied_at timestamp null);`,
	`CREATE TABLE plugin_registrations (id uuid primary key, name text not null unique, seam text not null, image text not null, endpoint text not null, service_identity_token_id uuid references tokens(id), enabled boolean not null default true, created_at timestamp not null, updated_at timestamp not null);`,
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
