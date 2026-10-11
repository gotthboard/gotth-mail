package ops

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"forgejo/gotthboard/gotth-mail/internal/authz"
	"forgejo/gotthboard/gotth-mail/internal/diag"
	"forgejo/gotthboard/gotth-mail/internal/store"
	"forgejo/gotthboard/gotth-mail/internal/testpg"
	"strings"
	"testing"
	"time"
)

const healthIssuer = "https://health.example/application/o/gotth-mail/"

func healthExec(t *testing.T, db *sql.DB, q string, args ...any) {
	t.Helper()
	if _, e := db.Exec(q, args...); e != nil {
		t.Fatal(e)
	}
}
func healthDB(t *testing.T) *sql.DB {
	t.Helper()
	db := testpg.DB(t, store.MigrateSQL)
	healthExec(t, db, "INSERT INTO domains(id,name,enabled,created_at,updated_at) VALUES ('00000000-0000-4000-8000-000000000601','private.test',true,now(),now()); INSERT INTO scim_resources(scope,resource_type,id,version,created_unix_nano,last_modified_unix_nano,data) VALUES ('private-scope','Group','private-group','v1',1,1,convert_to('{}','UTF8'))")
	for i, role := range []string{"global_admin", "domain_manager", "scoped_domain_access"} {
		var d any
		if i > 0 {
			d = "00000000-0000-4000-8000-000000000601"
		}
		healthExec(t, db, "INSERT INTO identity_group_role_mappings(id,issuer,scope,group_id,role,domain_id,created_at,updated_at) VALUES ($1,$2,'private-scope','private-group',$3,$4,now(),now())", fmt.Sprintf("00000000-0000-4000-8000-%012d", 610+i), healthIssuer, role, d)
	}
	return db
}
func healthSnapshot(t *testing.T, db *sql.DB) string {
	t.Helper()
	var out strings.Builder
	for _, table := range []string{"domains", "scim_resources", "scim_tombstones", "scim_group_members", "identity_group_role_mappings", "identity_refs", "role_bindings", "role_binding_group_sources", "audit_events"} {
		var s string
		if e := db.QueryRow("SELECT COALESCE(jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text),'[]')::text FROM " + table + " t").Scan(&s); e != nil {
			t.Fatal(e)
		}
		out.WriteString(s)
	}
	return out.String()
}
func TestIdentityHealthLocalInventoryAndPublicSeparation(t *testing.T) {
	db := healthDB(t)
	d := IdentityDiagnostic{DB: db, CurrentIssuer: healthIssuer}
	before := healthSnapshot(t, db)
	start := time.Now()
	h := d.Inspect(context.Background())
	t.Logf("native inventory M=3 roles=3 Groups=1 members=0 elapsed=%s", time.Since(start))
	if h.Status != OK || len(h.Mappings) != 3 || h.ObservedAt.IsZero() {
		t.Fatal(h)
	}
	if h.Mappings[0].DomainID != nil {
		t.Fatal("global target notNULL", h)
	}
	for _, row := range h.Mappings {
		if !row.Eligible || row.Scope != "private-scope" || row.GroupID != "private-group" {
			t.Fatal(row)
		}
	}
	healthExec(t, db, "CREATE ROLE health_readonly LOGIN; GRANT CONNECT ON DATABASE gotth_mail TO health_readonly; GRANT USAGE ON SCHEMA public TO health_readonly; GRANT SELECT ON ALL TABLES IN SCHEMA public TO health_readonly")
	var port string
	db.QueryRow("SHOW port").Scan(&port)
	ro, e := sql.Open("postgres", fmt.Sprintf("postgres://health_readonly@127.0.0.1:%s/gotth_mail?sslmode=disable&options=-c%%20default_transaction_read_only%%3Don", port))
	if e != nil {
		t.Fatal(e)
	}
	defer ro.Close()
	if _, e = ro.Exec("UPDATE identity_group_role_mappings SET revision=revision+1"); e == nil {
		t.Fatal("write-capable observer")
	}
	d.DB = ro
	in := DoctorInput{Identity: &d, ConfigOK: true, DatabaseOK: true, AuthentikOK: true, WebmailOK: true, Daemon: daemonFixture(), CertCheck: diag.CertCheck{Status: diag.CertOK}}
	pub := Doctor(context.Background(), in)
	local, details := DoctorLocal(context.Background(), in)
	if details == nil || details.Status != OK || pub.Status != Warn || local.Status != pub.Status {
		t.Fatal(pub, local, details)
	}
	b, _ := json.Marshal(pub)
	for _, secret := range []string{healthIssuer, "private-scope", "private-group", "00000000-0000-4000-8000-000000000601", "identity_details"} {
		if strings.Contains(string(b), secret) {
			t.Fatal("public disclosure", string(b))
		}
	}
	if healthSnapshot(t, db) != before {
		t.Fatal("diagnostic wrote")
	}
	other := d
	other.CurrentIssuer = "https://other.example/application/o/gotth-mail/"
	if h = other.Inspect(context.Background()); h.Status != Fail {
		t.Fatal("restartauthority ignored", h)
	}
	if h = d.Inspect(context.Background()); h.Status != OK {
		t.Fatal(h)
	}
	if healthSnapshot(t, db) != before {
		t.Fatal("restart wrote")
	}
}
func TestIdentityHealthExclusionsAndFailures(t *testing.T) {
	db := healthDB(t)
	d := IdentityDiagnostic{DB: db, CurrentIssuer: healthIssuer}
	for _, tc := range []struct{ q, restore string }{{"UPDATE identity_group_role_mappings SET enabled=false", "UPDATE identity_group_role_mappings SET enabled=true"}, {"UPDATE identity_group_role_mappings SET enabled=false,group_deleted=true", "UPDATE identity_group_role_mappings SET enabled=true,group_deleted=false"}, {"UPDATE domains SET enabled=false", "UPDATE domains SET enabled=true"}, {"UPDATE scim_resources SET scope='wrong-scope'", "UPDATE scim_resources SET scope='private-scope'"}, {"UPDATE scim_resources SET resource_type='User'", "UPDATE scim_resources SET resource_type='Group'"}, {"INSERT INTO scim_tombstones(scope,resource_type,id,version,deleted_unix_nano) VALUES ('private-scope','Group','private-group','v2',2)", "DELETE FROM scim_tombstones"}} {
		healthExec(t, db, tc.q)
		before := healthSnapshot(t, db)
		if h := d.Inspect(context.Background()); h.Status != Fail {
			t.Fatal("badlocaleligible", tc, h)
		}
		if healthSnapshot(t, db) != before {
			t.Fatal("failure wrote")
		}
		healthExec(t, db, tc.restore)
	}
	for _, issuer := range []string{"", "bad", "https://user:credential-canary@health.example/application/o/gotth-mail/"} {
		bad := d
		bad.CurrentIssuer = issuer
		h := bad.Inspect(context.Background())
		if h.Status == OK || h.Status == Unknown {
			t.Fatal(h)
		}
		b, _ := json.Marshal(h)
		if strings.Contains(string(b), "credential-canary") {
			t.Fatal("unsafeerror", string(b))
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if h := d.Inspect(ctx); h.Status != Fail {
		t.Fatal("cancel succeeded", h)
	}
	healthExec(t, db, "DELETE FROM identity_group_role_mappings")
	healthExec(t, db, "INSERT INTO identity_refs(id,provider,subject,issuer,created_at,updated_at) VALUES ('00000000-0000-4000-8000-000000000699','local','operator-only','local',now(),now()); INSERT INTO role_bindings(id,identity_ref_id,role,domain_id,created_at,updated_at) VALUES ('00000000-0000-4000-8000-000000000696','00000000-0000-4000-8000-000000000699','global_admin',NULL,now(),now()),('00000000-0000-4000-8000-000000000697','00000000-0000-4000-8000-000000000699','domain_manager','00000000-0000-4000-8000-000000000601',now(),now()),('00000000-0000-4000-8000-000000000698','00000000-0000-4000-8000-000000000699','scoped_domain_access','00000000-0000-4000-8000-000000000601',now(),now())")
	in := DoctorInput{Identity: &d, RoleMappings: []authz.RoleMapping{{AuthentikGroup: "admins", Role: authz.RoleGlobalAdmin, Verified: true}, {AuthentikGroup: "managers", Role: authz.RoleDomainManager, Domain: "private.test", Verified: true}, {AuthentikGroup: "access", Role: authz.RoleScopedDomainAccess, Domain: "private.test", Verified: true}}}
	if p := Doctor(context.Background(), in); !hasCheckReason(p.Checks, "local_role_coverage_incomplete") {
		t.Fatal("staticclaimauthorized", p)
	}
	healthExec(t, db, "ALTER TABLE identity_group_role_mappings RENAME TO hidden_mapping_canary")
	if h := d.Inspect(context.Background()); h.Status != Fail || strings.Contains(h.Reason, "hidden_mapping_canary") {
		t.Fatal(h)
	}
	db.Close()
	if h := d.Inspect(context.Background()); h.Status != Fail {
		t.Fatal(h)
	}
	if h := (IdentityDiagnostic{CurrentIssuer: healthIssuer}).Inspect(context.Background()); h.Status != Fail {
		t.Fatal(h)
	}
}

func TestIdentityHealthSnapshotAndEarlierDeadline(t *testing.T) {
	db := healthDB(t)
	d := IdentityDiagnostic{DB: db, CurrentIssuer: healthIssuer}
	healthExec(t, db, "ALTER TABLE identity_group_role_mappings RENAME TO health_mapping_rows; CREATE FUNCTION health_snapshot_guard() RETURNS boolean LANGUAGE plpgsql AS $$BEGIN IF current_setting('transaction_read_only')<>'on' OR current_setting('transaction_isolation')<>'repeatable read' THEN RAISE EXCEPTION 'not readonly repeatable snapshot'; END IF; RETURN true; END$$; CREATE VIEW identity_group_role_mappings AS SELECT * FROM health_mapping_rows WHERE health_snapshot_guard()")
	if h := d.Inspect(context.Background()); h.Status != OK {
		t.Fatal("snapshot contract", h)
	}
	tx, e := db.Begin()
	if e != nil {
		t.Fatal(e)
	}
	defer tx.Rollback()
	if _, e = tx.Exec("LOCK TABLE health_mapping_rows IN ACCESS EXCLUSIVE MODE"); e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	start := time.Now()
	h := d.Inspect(ctx)
	if h.Status != Fail || h.Reason != "local_identity_inspection_cancelled" || time.Since(start) > 2*time.Second {
		t.Fatal("deadlineignored", h, time.Since(start))
	}
}

func TestIdentityHealthMalformedRowsAndInactiveCoverage(t *testing.T) {
	db := healthDB(t)
	d := IdentityDiagnostic{DB: db, CurrentIssuer: healthIssuer}
	healthExec(t, db, "INSERT INTO identity_group_role_mappings(id,issuer,scope,group_id,role,enabled,created_at,updated_at) VALUES ('00000000-0000-4000-8000-000000000619',$1,'private-scope','inactive-group','global_admin',false,now(),now())", healthIssuer)
	if h := d.Inspect(context.Background()); h.Status != Warn || h.EligibleMappings != 3 || h.Mappings[3].Reason != "disabled_mapping" {
		t.Fatal(h)
	}
	healthExec(t, db, "ALTER TABLE identity_group_role_mappings DROP CONSTRAINT identity_group_role_mappings_role_check, DROP CONSTRAINT identity_group_role_mappings_check")
	for _, tc := range []struct{ q, want string }{{"UPDATE identity_group_role_mappings SET role='unknown' WHERE id='00000000-0000-4000-8000-000000000610'", "unknown_role"}, {"UPDATE identity_group_role_mappings SET role='global_admin',domain_id='00000000-0000-4000-8000-000000000601' WHERE id='00000000-0000-4000-8000-000000000610'", "invalid_role_domain"}, {"UPDATE identity_group_role_mappings SET role='scoped_domain_access',domain_id=NULL WHERE id='00000000-0000-4000-8000-000000000610'", "invalid_role_domain"}, {"UPDATE identity_group_role_mappings SET issuer='https://user:credential-canary@health.example/application/o/gotth-mail/' WHERE id='00000000-0000-4000-8000-000000000610'", "invalid_issuer"}} {
		healthExec(t, db, tc.q)
		h := d.Inspect(context.Background())
		if h.Status != Fail || h.Mappings[0].Reason != tc.want || h.Mappings[0].Eligible {
			t.Fatal(h)
		}
		b, _ := json.Marshal(h)
		if strings.Contains(string(b), "credential-canary") {
			t.Fatal("unsafe local issuer", string(b))
		}
	}
}

func TestIdentityHealthBoundedPopulation(t *testing.T) {
	db := healthDB(t)
	healthExec(t, db, "INSERT INTO scim_resources(scope,resource_type,id,version,created_unix_nano,last_modified_unix_nano,data) SELECT 'private-scope','Group','population-'||i,'v1',1,1,convert_to('{}','UTF8') FROM generate_series(1,32) i; INSERT INTO identity_group_role_mappings(id,issuer,scope,group_id,role,created_at,updated_at) SELECT ('00000000-0000-4000-8000-'||lpad((700+i)::text,12,'0'))::uuid,'https://health.example/application/o/gotth-mail/','private-scope','population-'||i,'global_admin',now(),now() FROM generate_series(1,32) i")
	before := healthSnapshot(t, db)
	start := time.Now()
	h := (IdentityDiagnostic{DB: db, CurrentIssuer: healthIssuer}).Inspect(context.Background())
	if h.Status != OK || len(h.Mappings) != 35 || h.EligibleMappings != 35 || before != healthSnapshot(t, db) {
		t.Fatal(h)
	}
	t.Logf("native inventory mappings=35 Groups=33 domains=1 members=0 rows=35 elapsed=%s; single diagnostic sample, not SLO", time.Since(start))
}

func TestDoctorConfiguredCheckPreservesMonitorKey(t *testing.T) {
	legacy := Doctor(context.Background(), DoctorInput{})
	configured := Doctor(context.Background(), DoctorInput{Identity: &IdentityDiagnostic{}})
	want := legacy.Checks[3].Name
	found := false
	for _, check := range configured.Checks {
		if check.Category == "identity" && check.Name == want {
			found = true
		}
	}
	if !found {
		t.Fatal("renamed durable notification state key", want, configured)
	}
}
