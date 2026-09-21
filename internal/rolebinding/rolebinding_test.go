package rolebinding

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"

	"forgejo/gotthboard/gotth-mail/internal/authn"
	"forgejo/gotthboard/gotth-mail/internal/store"
	"forgejo/gotthboard/gotth-mail/internal/testpg"
)

const (
	testIssuer   = "https://auth.example.test/application/o/gotth-mail/"
	testSubject  = "authentik-subject-1"
	testMailbox  = "admin@example.test"
	testIdentity = "00000000-0000-4000-8000-000000000183"
	testDomain   = "00000000-0000-4000-8000-000000000181"
)

func TestGlobalRoleGrantRevokeProjectsIntoExistingSession(t *testing.T) {
	db := roleDB(t)
	service := testService(db)
	request := validRequest()
	ctx := context.Background()
	assertSessionRole(t, db, "", "")

	grant, err := service.Preview(ctx, request)
	if err != nil || grant.Operation != OperationGrant || grant.IdentityID != testIdentity || grant.PlanID == "" {
		t.Fatalf("grant plan=%#v err=%v", grant, err)
	}
	encoded, err := json.Marshal(grant)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encoded, []byte(testIssuer)) || bytes.Contains(encoded, []byte(testSubject)) {
		t.Fatalf("plan disclosed identity provider material: %s", encoded)
	}
	if _, err := service.Apply(ctx, request, strings.Repeat("0", 64)); err == nil {
		t.Fatal("wrong confirmation accepted")
	}
	assertCounts(t, db, 0, 0)
	result, err := service.Apply(ctx, request, grant.PlanID)
	if err != nil || !result.Changed || result.Plan.Operation != OperationGrant {
		t.Fatalf("grant result=%#v err=%v", result, err)
	}
	assertCounts(t, db, 1, 1)
	assertSessionRole(t, db, RoleGlobalAdmin, "")

	unchanged, err := service.Preview(ctx, request)
	if err != nil || unchanged.Operation != "unchanged" || unchanged.PlanID == grant.PlanID {
		t.Fatalf("unchanged plan=%#v err=%v", unchanged, err)
	}
	result, err = service.Apply(ctx, request, unchanged.PlanID)
	if err != nil || result.Changed {
		t.Fatalf("unchanged result=%#v err=%v", result, err)
	}
	assertCounts(t, db, 1, 1)

	revokeRequest := request
	revokeRequest.Operation = OperationRevoke
	revoke, err := service.Preview(ctx, revokeRequest)
	if err != nil || revoke.Operation != OperationRevoke {
		t.Fatalf("revoke plan=%#v err=%v", revoke, err)
	}
	result, err = service.Apply(ctx, revokeRequest, revoke.PlanID)
	if err != nil || !result.Changed {
		t.Fatalf("revoke result=%#v err=%v", result, err)
	}
	assertCounts(t, db, 0, 2)
	assertSessionRole(t, db, "", "")

	rows, err := db.Query(`SELECT action, before_redacted_json, after_redacted_json FROM audit_events ORDER BY action`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var action, before, after string
		if err := rows.Scan(&action, &before, &after); err != nil {
			t.Fatal(err)
		}
		if !strings.HasPrefix(action, "identity.role_binding.") || strings.Contains(before+after, testIssuer) || strings.Contains(before+after, testSubject) || strings.Contains(before+after, testMailbox) {
			t.Fatalf("unsafe audit action=%q before=%q after=%q", action, before, after)
		}
		switch action {
		case "identity.role_binding.grant":
			if before != "null" || !strings.Contains(after, RoleGlobalAdmin) {
				t.Fatalf("grant audit before=%q after=%q", before, after)
			}
		case "identity.role_binding.revoke":
			if !strings.Contains(before, RoleGlobalAdmin) || after != "null" {
				t.Fatalf("revoke audit before=%q after=%q", before, after)
			}
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
}

func TestScopedRolesAndDatabaseConstraints(t *testing.T) {
	db := roleDB(t)
	service := testService(db)
	ctx := context.Background()
	for _, role := range []string{RoleDomainManager, RoleScopedDomainAccess} {
		request := validRequest()
		request.Role = role
		request.Domain = "example.test"
		plan, err := service.Preview(ctx, request)
		if err != nil || plan.Operation != OperationGrant {
			t.Fatalf("%s plan=%#v err=%v", role, plan, err)
		}
		if _, err := service.Apply(ctx, request, plan.PlanID); err != nil {
			t.Fatal(err)
		}
		assertSessionRole(t, db, role, "example.test")
	}
	if _, err := db.Exec(`INSERT INTO role_bindings(id,identity_ref_id,role,domain_id,created_at,updated_at) VALUES ('00000000-0000-4000-8000-000000000191',$1,'global_admin',$2,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)`, testIdentity, testDomain); err == nil {
		t.Fatal("global administrator with domain passed database constraint")
	}
	if _, err := db.Exec(`INSERT INTO role_bindings(id,identity_ref_id,role,domain_id,created_at,updated_at) VALUES ('00000000-0000-4000-8000-000000000192',$1,'domain_manager',NULL,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)`, testIdentity); err == nil {
		t.Fatal("domain manager without domain passed database constraint")
	}
	if _, err := db.Exec(`INSERT INTO role_bindings(id,identity_ref_id,role,domain_id,created_at,updated_at) VALUES ('00000000-0000-4000-8000-000000000193',$1,'domain_manager',$2,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)`, testIdentity, testDomain); err == nil {
		t.Fatal("duplicate scoped binding passed database constraint")
	}
}

func TestRoleBindingRejectsInvalidExactAndDisabledState(t *testing.T) {
	db := roleDB(t)
	service := testService(db)
	ctx := context.Background()
	if _, err := (Service{}).Preview(ctx, validRequest()); err == nil {
		t.Fatal("missing database accepted")
	}
	if _, err := (Service{}).Apply(ctx, validRequest(), strings.Repeat("0", 64)); err == nil {
		t.Fatal("apply without database accepted")
	}
	mutations := []func(*Request){
		func(value *Request) { value.Operation = "replace" },
		func(value *Request) { value.Issuer = "http://auth.example.test/application/o/gotth-mail/" },
		func(value *Request) { value.Issuer = " " + value.Issuer },
		func(value *Request) { value.Subject = "bad\nsubject" },
		func(value *Request) { value.Subject = value.Subject + " " },
		func(value *Request) { value.Mailbox = "not-mail" },
		func(value *Request) { value.Role = "owner" },
		func(value *Request) { value.Domain = "example.test" },
		func(value *Request) { value.Role, value.Domain = RoleDomainManager, "" },
	}
	for index, mutate := range mutations {
		request := validRequest()
		mutate(&request)
		if _, err := service.Preview(ctx, request); err == nil {
			t.Errorf("invalid request %d accepted", index)
		}
	}
	for _, mutate := range []func(*Request){
		func(value *Request) { value.Issuer = "https://other.example.test/application/o/gotth-mail/" },
		func(value *Request) { value.Subject = "other" },
		func(value *Request) { value.Mailbox = "other@example.test" },
	} {
		request := validRequest()
		mutate(&request)
		if _, err := service.Preview(ctx, request); err == nil {
			t.Fatal("inexact identity accepted")
		}
	}
	if _, err := db.Exec(`UPDATE mailboxes SET enabled=false`); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Preview(ctx, validRequest()); err == nil {
		t.Fatal("grant for disabled mailbox accepted")
	}
}

func TestRoleBindingDisabledStateAndRevokeRecovery(t *testing.T) {
	t.Run("mailbox domain blocks grant", func(t *testing.T) {
		db := roleDB(t)
		if _, err := db.Exec(`UPDATE domains SET enabled=false WHERE id=$1`, testDomain); err != nil {
			t.Fatal(err)
		}
		if _, err := testService(db).Preview(context.Background(), validRequest()); err == nil {
			t.Fatal("grant for disabled mailbox domain accepted")
		}
	})
	t.Run("target domain blocks scoped grant", func(t *testing.T) {
		db := roleDB(t)
		if _, err := db.Exec(`INSERT INTO domains(id,name,enabled,created_at,updated_at) VALUES ('00000000-0000-4000-8000-000000000184','disabled.example.test',false,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)`); err != nil {
			t.Fatal(err)
		}
		request := validRequest()
		request.Role = RoleDomainManager
		request.Domain = "disabled.example.test"
		if _, err := testService(db).Preview(context.Background(), request); err == nil {
			t.Fatal("grant for disabled target domain accepted")
		}
	})
	t.Run("revoke remains available", func(t *testing.T) {
		db := roleDB(t)
		service := testService(db)
		request := validRequest()
		grant, err := service.Preview(context.Background(), request)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := service.Apply(context.Background(), request, grant.PlanID); err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec(`UPDATE mailboxes SET enabled=false; UPDATE domains SET enabled=false`); err != nil {
			t.Fatal(err)
		}
		request.Operation = OperationRevoke
		revoke, err := service.Preview(context.Background(), request)
		if err != nil || revoke.Operation != OperationRevoke {
			t.Fatalf("revoke preview=%#v err=%v", revoke, err)
		}
		if _, err := service.Apply(context.Background(), request, revoke.PlanID); err != nil {
			t.Fatal(err)
		}
		assertCounts(t, db, 0, 2)
	})
}

func TestRoleBindingRejectsStalePlanAndRollsBackAuditFailure(t *testing.T) {
	t.Run("stale", func(t *testing.T) {
		db := roleDB(t)
		service := testService(db)
		request := validRequest()
		plan, err := service.Preview(context.Background(), request)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec(`INSERT INTO role_bindings(id,identity_ref_id,role,domain_id,created_at,updated_at) VALUES ('00000000-0000-4000-8000-000000000194',$1,'global_admin',NULL,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)`, testIdentity); err != nil {
			t.Fatal(err)
		}
		if _, err := service.Apply(context.Background(), request, plan.PlanID); err == nil || !strings.Contains(err.Error(), "confirmation digest") {
			t.Fatalf("stale apply err=%v", err)
		}
		assertCounts(t, db, 1, 0)
	})
	t.Run("audit rollback", func(t *testing.T) {
		db := roleDB(t)
		if _, err := db.Exec(`CREATE FUNCTION reject_role_audit() RETURNS trigger AS $$ BEGIN IF NEW.action='identity.role_binding.grant' THEN RAISE EXCEPTION 'forced role audit failure'; END IF; RETURN NEW; END; $$ LANGUAGE plpgsql; CREATE TRIGGER reject_role_audit BEFORE INSERT ON audit_events FOR EACH ROW EXECUTE FUNCTION reject_role_audit()`); err != nil {
			t.Fatal(err)
		}
		service := testService(db)
		request := validRequest()
		plan, err := service.Preview(context.Background(), request)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := service.Apply(context.Background(), request, plan.PlanID); err == nil || !strings.Contains(err.Error(), "forced role audit failure") {
			t.Fatalf("audit failure err=%v", err)
		}
		assertCounts(t, db, 0, 0)
	})
}

func TestConcurrentRoleGrantCreatesOneBinding(t *testing.T) {
	db := roleDB(t)
	request := validRequest()
	preview, err := testService(db).Preview(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	var wait sync.WaitGroup
	wait.Add(2)
	results := make(chan error, 2)
	for range 2 {
		go func() {
			defer wait.Done()
			_, err := testService(db).Apply(context.Background(), request, preview.PlanID)
			results <- err
		}()
	}
	wait.Wait()
	close(results)
	successes := 0
	for err := range results {
		if err == nil {
			successes++
		}
	}
	if successes != 1 {
		t.Fatalf("concurrent successes=%d want 1", successes)
	}
	assertCounts(t, db, 1, 1)
}

func validRequest() Request {
	return Request{Operation: OperationGrant, Issuer: testIssuer, Subject: testSubject, Mailbox: testMailbox, Role: RoleGlobalAdmin}
}

func testService(db *sql.DB) Service {
	entropy := make([]byte, 64)
	for index := range entropy {
		entropy[index] = byte(index + 1)
	}
	return Service{DB: db, Now: func() time.Time { return time.Unix(1800, 0).UTC() }, Entropy: bytes.NewReader(entropy)}
}

func roleDB(t *testing.T) *sql.DB {
	t.Helper()
	db := testpg.DB(t, store.MigrateSQL)
	statements := []string{
		`INSERT INTO domains(id,name,enabled,created_at,updated_at) VALUES ('` + testDomain + `','example.test',true,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)`,
		`INSERT INTO mailboxes(id,domain_id,local_part,display_name,enabled,created_at,updated_at) VALUES ('00000000-0000-4000-8000-000000000182','` + testDomain + `','admin','Admin',true,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)`,
		`INSERT INTO identity_refs(id,provider,issuer,subject,mailbox_id,created_at,updated_at) VALUES ('` + testIdentity + `','authentik','` + testIssuer + `','` + testSubject + `','00000000-0000-4000-8000-000000000182',CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)`,
	}
	for _, statement := range statements {
		if _, err := db.Exec(statement); err != nil {
			t.Fatal(err)
		}
	}
	now := time.Now().UTC()
	if _, err := db.Exec(`INSERT INTO sessions(id,identity_ref_id,csrf_secret_hash,auth_method,created_at,expires_at,last_seen_at) VALUES ('existing-session',$1,'hash','oidc',$2,$3,$2)`, testIdentity, now.Add(-time.Minute), now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	return db
}

func assertCounts(t *testing.T, db *sql.DB, bindings, audits int) {
	t.Helper()
	var gotBindings, gotAudits int
	if err := db.QueryRow(`SELECT count(*) FROM role_bindings`).Scan(&gotBindings); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT count(*) FROM audit_events WHERE action LIKE 'identity.role_binding.%'`).Scan(&gotAudits); err != nil {
		t.Fatal(err)
	}
	if gotBindings != bindings || gotAudits != audits {
		t.Fatalf("counts bindings=%d audits=%d want %d/%d", gotBindings, gotAudits, bindings, audits)
	}
}

func assertSessionRole(t *testing.T, db *sql.DB, role, domain string) {
	t.Helper()
	bound, ok := (authn.SQLStore{DB: db}).BoundSession(context.Background(), "existing-session", time.Now().UTC())
	if !ok {
		t.Fatal("existing session did not survive role mutation")
	}
	if role == "" {
		if len(bound.Roles) != 0 {
			t.Fatalf("roles=%#v want none", bound.Roles)
		}
		return
	}
	found := false
	for _, assignment := range bound.Roles {
		if string(assignment.Role) == role && assignment.Domain == domain {
			found = true
		}
	}
	if !found {
		t.Fatalf("roles=%#v missing %s/%s", bound.Roles, role, domain)
	}
}
