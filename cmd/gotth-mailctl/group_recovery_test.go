package main

import (
	"context"
	"encoding/json"
	"fmt"
	"forgejo/gotthboard/gotth-mail/internal/rolebinding"
	"forgejo/gotthboard/gotth-mail/internal/store"
	"forgejo/gotthboard/gotth-mail/internal/testpg"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCLIGroupRecoveryClosedFlags(t *testing.T) {
	base := []string{"identity", "group-feature-disable", "preview", "--config", "c"}
	if _, e := recoveryFlags(base); e != nil {
		t.Fatal(e)
	}
	for _, tail := range [][]string{{"--format", "json"}, {"--format", "text"}, {"--issuer", "x"}, {"--fenced", "true"}, {"--role", "global_admin"}, {"--confirm", "x"}, {"--config", "c"}, {"--config"}, {"--config", ""}} {
		if _, e := recoveryFlags(append(append([]string{}, base...), tail...)); e == nil {
			t.Fatal("accepted flags", tail)
		}
	}
	for _, args := range [][]string{nil, {"identity", "group-feature-disable", "bad"}, {"identity", "group-feature-disable", "apply", "--config", "c"}, {"identity", "group-feature-disable", "preview"}} {
		if _, e := recoveryFlags(args); e == nil {
			t.Fatal("accepted mode", args)
		}
	}
	base[2] = "apply"
	if got, e := recoveryFlags(append(base, "--confirm", strings.Repeat("a", 64))); e != nil || len(got) != 64 {
		t.Fatal(got, e)
	}
}
func TestCLIGroupRecoveryReal(t *testing.T) {
	db := testpg.DB(t, store.MigrateSQL)
	bin := doctorBinary(t)
	ctx := context.Background()
	runSQL := func(q string, args ...any) {
		t.Helper()
		if _, e := db.Exec(q, args...); e != nil {
			t.Fatal(e)
		}
	}
	var port string
	db.QueryRow("SHOW port").Scan(&port)
	var ver int
	db.QueryRow("SHOW server_version_num").Scan(&ver)
	runSQL("CREATE ROLE recovery_cli LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS; GRANT USAGE ON SCHEMA public TO recovery_cli; GRANT SELECT ON identity_group_role_mappings,role_bindings,role_binding_group_sources,identity_refs,domains,schema_migrations TO recovery_cli; GRANT UPDATE ON identity_group_role_mappings,role_bindings TO recovery_cli; GRANT DELETE ON role_bindings,role_binding_group_sources TO recovery_cli; GRANT INSERT ON audit_events TO recovery_cli")
	priv := "UPDATE"
	if ver >= 170000 {
		priv = "MAINTAIN"
	}
	runSQL("GRANT " + priv + " ON schema_migrations TO recovery_cli")
	runSQL("INSERT INTO domains(id,name,enabled,created_at,updated_at) VALUES ('00000000-0000-4000-8000-000000000980','example.test',true,now(),now())")
	for i, role := range []string{"global_admin", "domain_manager", "scoped_domain_access"} {
		var d any
		if i > 0 {
			d = "00000000-0000-4000-8000-000000000980"
		}
		runSQL("INSERT INTO identity_group_role_mappings(id,issuer,scope,group_id,role,domain_id,created_at,updated_at) VALUES ($1,'https://private-issuer.example/application/o/gotth-mail/','private-scope','private-group',$2,$3,now(),now())", fmt.Sprintf("00000000-0000-4000-8000-%012d", 981+i), role, d)
	}
	root := t.TempDir()
	cfg := filepath.Join(root, "config.yaml")
	body := fmt.Sprintf("server:\n  public_url: https://mail.example.test\n  listen: ':8080'\n  environment: development\ndatabase:\n  dsn: 'postgres://recovery_cli@127.0.0.1:%s/gotth_mail?sslmode=disable'\ntls:\n  mode: manual\n  cert_path: cert.pem\n  key_path: key.pem\nauthentik:\n  enabled: true\n  base_url: https://not-authority.example\nroles:\n  global_admin_group: admins\n  domain_manager_group: managers\n  scoped_domain_group_prefix: domain-\nrender:\n  staging_dir: %s\n  applied_dir: %s\n", port, filepath.Join(root, "stage"), filepath.Join(root, "applied"))
	if e := os.WriteFile(cfg, []byte(body), 0600); e != nil {
		t.Fatal(e)
	}
	base := []string{"identity", "group-feature-disable", "preview", "--config", cfg}
	before := doctorSnapshot(t, db)
	out, code := doctorCall(t, bin, "/does/not/exist", base...)
	var p rolebinding.RecoveryPlan
	if e := json.Unmarshal(out, &p); e != nil || code != 0 || p.ChangedMappings != 3 || p.Schema != "gotth-mail/group-feature-disable-plan/v1" || before != doctorSnapshot(t, db) {
		t.Fatal("actual preview", code, string(out), e)
	}
	for _, secret := range []string{"private-issuer", "private-scope", "private-group"} {
		if strings.Contains(string(out), secret) {
			t.Fatal("output leaked", secret)
		}
	}
	apply := append([]string{}, base...)
	apply[2] = "apply"
	bad := append(append([]string{}, apply...), "--confirm", strings.Repeat("0", 64))
	if out, code = doctorCall(t, bin, "/does/not/exist", bad...); code != 1 || before != doctorSnapshot(t, db) {
		t.Fatal("stale apply", code, string(out))
	}
	runSQL("CREATE FUNCTION recovery_cli_audit_fail() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'credential-canary raw SQL'; END$$; CREATE TRIGGER recovery_cli_fail BEFORE INSERT ON audit_events FOR EACH ROW EXECUTE FUNCTION recovery_cli_audit_fail()")
	good := append(append([]string{}, apply...), "--confirm", p.PlanID)
	out, code = doctorCall(t, bin, "/does/not/exist", good...)
	if code != 1 || strings.Contains(string(out), "credential-canary") || before != doctorSnapshot(t, db) {
		t.Fatal("unsafe/partial failure", code, string(out))
	}
	runSQL("DROP TRIGGER recovery_cli_fail ON audit_events")
	out, code = doctorCall(t, bin, "/does/not/exist", good...)
	var result rolebinding.RecoveryResult
	if e := json.Unmarshal(out, &result); e != nil || code != 0 || !result.Changed {
		t.Fatal(code, string(out), e)
	}
	var n int
	if e := db.QueryRowContext(ctx, "SELECT count(*) FROM identity_group_role_mappings WHERE enabled").Scan(&n); e != nil || n != 0 {
		t.Fatal(n, e)
	}
	out, code = doctorCall(t, bin, "", base...)
	if e := json.Unmarshal(out, &p); e != nil || code != 0 || p.ChangedMappings != 0 {
		t.Fatal(code, string(out), e)
	}
	before = doctorSnapshot(t, db)
	out, code = doctorCall(t, bin, "", append(apply, "--confirm", p.PlanID)...)
	if code != 0 || before != doctorSnapshot(t, db) {
		t.Fatal("noop", code, string(out))
	}
	for _, args := range [][]string{{"identity", "group-feature-disable", "preview", "--config", "missing-secret-canary"}, append(append([]string{}, base...), "--format", "text"), {"identity", "group-feature-disable", "apply", "--config", cfg}} {
		out, code = doctorCall(t, bin, "", args...)
		if code != 1 || strings.Contains(string(out), "secret-canary") {
			t.Fatal("usage safety", code, string(out))
		}
	}
	runSQL("ALTER TABLE identity_group_role_mappings RENAME TO recovery_missing")
	out, code = doctorCall(t, bin, "", base...)
	if code != 1 || strings.Contains(string(out), "recovery_missing") {
		t.Fatal("schema failure", code, string(out))
	}
	var exists bool
	if e := db.QueryRow("SELECT to_regclass('identity_group_role_mappings') IS NOT NULL").Scan(&exists); e != nil || exists {
		t.Fatal("CLI bootstrapped schema", exists, e)
	}
}
