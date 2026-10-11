package main

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"fmt"
	"forgejo/gotthboard/gotth-mail/internal/store"
	"forgejo/gotthboard/gotth-mail/internal/testpg"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func doctorBinary(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "gotth-mailctl")
	cmd := exec.Command("go", "build", "-p=1", "-o", bin, ".")
	t.Logf("compile argv=%q inherited lane env", cmd.Args)
	out, e := cmd.CombinedOutput()
	if e != nil {
		t.Fatal(e, string(out))
	}
	b, e := os.ReadFile(bin)
	if e != nil {
		t.Fatal(e)
	}
	t.Logf("compile_exit=0 binary_sha256=%x", sha256.Sum256(b))
	return bin
}
func doctorCall(t *testing.T, bin, authority string, args ...string) ([]byte, int) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Env = append(os.Environ(), "GOTTH_MAIL_IDENTITY_RUNTIME_CONFIG_FILE="+authority)
	out, e := cmd.CombinedOutput()
	code := -1
	if cmd.ProcessState != nil {
		code = cmd.ProcessState.ExitCode()
	}
	t.Logf("argv=%q authority_file=%q native_exit=%d err=%v", cmd.Args, authority, code, e)
	return out, code
}
func TestCLIDoctorLegacyContractReal(t *testing.T) {
	bin := doctorBinary(t)
	for _, format := range []string{"text", "json"} {
		out, code := doctorCall(t, bin, "/does/not/exist", "doctor", "--format", format)
		t.Logf("legacy_%s=%s", format, out)
		if code != 0 || !strings.Contains(string(out), "missing_required_mapping:global_admin") || strings.Contains(string(out), "identity_details") {
			t.Fatal(code, string(out))
		}
		if format == "text" && !strings.HasPrefix(string(out), "status: fail\n") {
			t.Fatal(string(out))
		}
		if format == "json" {
			var v struct{ Status string }
			if e := json.Unmarshal(out, &v); e != nil || v.Status != "fail" {
				t.Fatal(e, string(out))
			}
		}
	}
	if out, code := doctorCall(t, bin, "", "doctor", "--format", "xml"); code != 1 {
		t.Fatal(code, string(out))
	}
}
func TestCLIDoctorConfiguredReal(t *testing.T) {
	db := testpg.DB(t, store.MigrateSQL)
	var port string
	if e := db.QueryRow("SHOW port").Scan(&port); e != nil {
		t.Fatal(e)
	}
	bin := doctorBinary(t)
	root := t.TempDir()
	cfg := filepath.Join(root, "config.yaml")
	authority := filepath.Join(root, "authority.json")
	body := fmt.Sprintf("server:\n  public_url: https://mail.example.test\n  listen: ':8080'\n  environment: development\ndatabase:\n  dsn: 'postgres://gotth_mail@127.0.0.1:%s/gotth_mail?sslmode=disable'\ntls:\n  mode: manual\n  cert_path: cert.pem\n  key_path: key.pem\nauthentik:\n  enabled: true\n  base_url: https://not-authority.example\nroles:\n  global_admin_group: admins\n  domain_manager_group: managers\n  scoped_domain_group_prefix: domain-\nrender:\n  staging_dir: %s\n  applied_dir: %s\n", port, filepath.Join(root, "staged"), filepath.Join(root, "applied"))
	if e := os.WriteFile(cfg, []byte(body), 0600); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(authority, []byte(`{"GOTTH_MAIL_AUTHENTIK_ISSUER":"https://auth.example/application/o/gotth-mail/"}`), 0600); e != nil {
		t.Fatal(e)
	}
	out, code := doctorCall(t, bin, authority, "doctor", "--config", cfg, "--format", "json")
	var report struct {
		Status          string
		IdentityDetails *struct{ Reason string } `json:"identity_details"`
	}
	if e := json.Unmarshal(out, &report); e != nil || code != 0 || report.IdentityDetails == nil || report.IdentityDetails.Reason != "local_role_coverage_incomplete" {
		t.Fatal("configured inventory missing", code, string(out), e)
	}
	execSQL := func(q string, args ...any) {
		t.Helper()
		if _, e := db.Exec(q, args...); e != nil {
			t.Fatal(e)
		}
	}
	execSQL("INSERT INTO domains(id,name,enabled,created_at,updated_at) VALUES ('00000000-0000-4000-8000-000000000691','private.test',true,now(),now()); INSERT INTO scim_resources(scope,resource_type,id,version,created_unix_nano,last_modified_unix_nano,data) VALUES ('private-cli-scope','Group','private-cli-group','v1',1,1,convert_to('{}','UTF8'))")
	for i, role := range []string{"global_admin", "domain_manager", "scoped_domain_access"} {
		var domain any
		if i > 0 {
			domain = "00000000-0000-4000-8000-000000000691"
		}
		execSQL("INSERT INTO identity_group_role_mappings(id,issuer,scope,group_id,role,domain_id,created_at,updated_at) VALUES ($1,'https://auth.example/application/o/gotth-mail/','private-cli-scope','private-cli-group',$2,$3,now(),now())", fmt.Sprintf("00000000-0000-4000-8000-%012d", 692+i), role, domain)
	}
	before := doctorSnapshot(t, db)
	for _, format := range []string{"json", "text"} {
		out, code = doctorCall(t, bin, authority, "doctor", "--config", cfg, "--format", format)
		if code != 0 || !strings.Contains(string(out), "local_role_coverage_complete") || !strings.Contains(string(out), "private-cli-group") || strings.Contains(string(out), "not-authority.example") {
			t.Fatal("actual local inventory", code, string(out))
		}
	}
	if !strings.Contains(string(out), "status: warn") || !strings.Contains(string(out), "not_inspected_in_configured_cli") {
		t.Fatal("CLI claimed runtime health without a runtime", string(out))
	}
	if before != doctorSnapshot(t, db) {
		t.Fatal("configured doctor wrote")
	}
	for _, tc := range []struct{ body, want string }{{`{"GOTTH_MAIL_AUTHENTIK_ISSUER":"https://other.example/application/o/gotth-mail/"}`, "local_role_coverage_incomplete"}, {`{"secret":"credential-canary"}`, "local_identity_authority_invalid"}} {
		if e := os.WriteFile(authority, []byte(tc.body), 0600); e != nil {
			t.Fatal(e)
		}
		out, code = doctorCall(t, bin, authority, "doctor", "--config", cfg, "--format", "json")
		if code != 0 || !strings.Contains(string(out), tc.want) || strings.Contains(string(out), "credential-canary") {
			t.Fatal(code, string(out))
		}
	}
	out, code = doctorCall(t, bin, "", "doctor", "--config", cfg, "--format", "json")
	if code != 0 || !strings.Contains(string(out), "local_identity_authority_missing") {
		t.Fatal("missingauthorityfallback", code, string(out))
	}
	if e := os.WriteFile(authority, []byte(`{"GOTTH_MAIL_AUTHENTIK_ISSUER":"https://auth.example/application/o/gotth-mail/"}`), 0600); e != nil {
		t.Fatal(e)
	}
	if e := os.Chmod(authority, 0644); e != nil {
		t.Fatal(e)
	}
	out, code = doctorCall(t, bin, authority, "doctor", "--config", cfg, "--format", "json")
	if code != 0 || !strings.Contains(string(out), "local_identity_authority_invalid") {
		t.Fatal(code, string(out))
	}
	os.Chmod(authority, 0600)
	execSQL("ALTER TABLE identity_group_role_mappings RENAME TO doctor_missing_schema")
	out, code = doctorCall(t, bin, authority, "doctor", "--config", cfg, "--format", "json")
	if code != 0 || !strings.Contains(string(out), "local_identity_schema_or_query_unavailable") || strings.Contains(string(out), "doctor_missing_schema") {
		t.Fatal(code, string(out))
	}
	var present bool
	if e := db.QueryRow("SELECT to_regclass('identity_group_role_mappings') IS NOT NULL").Scan(&present); e != nil || present {
		t.Fatal("doctor bootstrapped schema", present, e)
	}
	for _, args := range [][]string{{"doctor", "--config", cfg, "--format", "xml"}, {"doctor", "--config"}, {"doctor", "--config", "missing-credential-canary"}, {"doctor", "--config", cfg, "--unknown", "x"}} {
		out, code = doctorCall(t, bin, authority, args...)
		if code != 1 || strings.Contains(string(out), "credential-canary") {
			t.Fatal("configuration error contract", code, string(out))
		}
	}

}

func doctorSnapshot(t *testing.T, db *sql.DB) string {
	t.Helper()
	var out strings.Builder
	for _, table := range []string{"domains", "scim_resources", "identity_group_role_mappings", "identity_refs", "role_bindings", "role_binding_group_sources", "audit_events", "schema_migrations"} {
		var s string
		if e := db.QueryRow("SELECT COALESCE(jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text),'[]')::text FROM " + table + " t").Scan(&s); e != nil {
			t.Fatal(e)
		}
		out.WriteString(s)
	}
	return out.String()
}
