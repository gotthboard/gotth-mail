package api

import (
	"context"
	"encoding/json"
	"forgejo/gotthboard/gotth-mail/internal/ops"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDoctorPublicIdentityInventoryAndErrorRedaction(t *testing.T) {
	db, ids, _, _, groups := projectionFixture(t)
	projectionExec(t, db, "INSERT INTO identity_group_role_mappings(id,issuer,scope,group_id,role,domain_id,created_at,updated_at) SELECT '00000000-0000-4000-8000-000000000651',issuer,scope,group_id,'global_admin',NULL,now(),now() FROM identity_group_role_mappings LIMIT 1")
	projectionExec(t, db, "INSERT INTO identity_group_role_mappings(id,issuer,scope,group_id,role,domain_id,created_at,updated_at) SELECT '00000000-0000-4000-8000-000000000652',issuer,scope,group_id,'scoped_domain_access',domain_id,now(),now() FROM identity_group_role_mappings WHERE role='domain_manager' LIMIT 1")
	var domain string
	db.QueryRow("SELECT id::text FROM domains WHERE name='example.test'").Scan(&domain)
	server := Server{AuditDB: db, CurrentIssuer: projectionIssuer, Identity: ids}
	before := projectionSnapshot(t, db)
	check := func(s Server, want ops.Status, ctx context.Context) {
		t.Helper()
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/api/v1/doctor", nil).WithContext(ctx)
		s.Handler().ServeHTTP(rr, req)
		if rr.Code != 200 {
			t.Fatal(rr.Code, rr.Body.String())
		}
		var report ops.DoctorReport
		if e := json.Unmarshal(rr.Body.Bytes(), &report); e != nil {
			t.Fatal(e)
		}
		found := false
		for _, c := range report.Checks {
			if c.Name == "authentik-role-mapping" {
				found = true
				if c.Status != want {
					t.Fatal(c, want)
				}
			}
		}
		if !found {
			t.Fatal("actual public caller omittedinventory", report)
		}
		for _, secret := range append(groups, projectionIssuer, provisioningScope("scim-test"), domain, "projection-subject", "credential-canary", "raw-error-canary", "identity_details") {
			if secret != "" && strings.Contains(rr.Body.String(), secret) {
				t.Fatal("public identity disclosure", rr.Body.String())
			}
		}
	}
	check(server, ops.OK, context.Background())
	if before != projectionSnapshot(t, db) {
		t.Fatal("public read wrote")
	}
	server.CurrentIssuer = "https://other.example/application/o/gotth-mail/"
	check(server, ops.Fail, context.Background())
	server.CurrentIssuer = ""
	check(server, ops.Warn, context.Background())
	server.CurrentIssuer = projectionIssuer
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	check(server, ops.Fail, ctx)
	projectionExec(t, db, "ALTER TABLE identity_group_role_mappings RENAME TO doctor_private_rows; CREATE FUNCTION doctor_error_guard() RETURNS boolean LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'raw-error-canary credential-canary'; END$$; CREATE VIEW identity_group_role_mappings AS SELECT * FROM doctor_private_rows WHERE doctor_error_guard()")
	check(server, ops.Fail, context.Background())
	server.AuditDB = nil
	check(server, ops.Fail, context.Background())
}
