package rolebinding

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

const groupBinding = "00000000-0000-4000-8000-000000000920"

func seedGroupOrigins(t *testing.T, db *sql.DB, operator bool) {
	t.Helper()
	if _, err := db.Exec(`INSERT INTO role_bindings(id,identity_ref_id,role,domain_id,operator_owned,created_at,updated_at) VALUES ($1,$2,'domain_manager',$3,$4,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)`, groupBinding, testIdentity, testDomain, operator); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"00000000-0000-4000-8000-000000000921", "00000000-0000-4000-8000-000000000922"} {
		if _, err := db.Exec(`INSERT INTO identity_group_role_mappings(id,issuer,scope,group_id,role,domain_id,created_at,updated_at) VALUES ($1::uuid,$2,'scope',$1::uuid::text,'domain_manager',$3,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)`, id, testIssuer, testDomain); err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec("INSERT INTO role_binding_group_sources VALUES ($1,$2)", groupBinding, id); err != nil {
			t.Fatal(err)
		}
	}
}

func scopedRequest() Request {
	r := validRequest()
	r.Role = RoleDomainManager
	r.Domain = "example.test"
	return r
}

func TestOperatorOriginPreservesTwoGroups(t *testing.T) {
	db := roleDB(t)
	seedGroupOrigins(t, db, false)
	service := testService(db)
	service.CurrentIssuer = testIssuer
	ctx := context.Background()
	request := scopedRequest()
	plan, err := service.Preview(ctx, request)
	if err != nil || plan.Operation != OperationGrant {
		t.Fatalf("Group-only grant must add operator origin: plan=%+v err=%v", plan, err)
	}
	if _, err := service.Apply(ctx, request, plan.PlanID); err != nil {
		t.Fatal(err)
	}
	assertOriginRow(t, db, true, 2, 2)
	request.Operation = OperationRevoke
	plan, err = service.Preview(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Apply(ctx, request, plan.PlanID); err != nil {
		t.Fatal(err)
	}
	assertOriginRow(t, db, false, 3, 2)
	if !plan.EffectiveAfter {
		t.Fatal("revoke hid surviving Group authority")
	}
	var auditJSON string
	if err := db.QueryRow("SELECT before_redacted_json FROM audit_events WHERE action='identity.role_binding.revoke'").Scan(&auditJSON); err != nil {
		t.Fatal(err)
	}
	var auditFields map[string]any
	if err := json.Unmarshal([]byte(auditJSON), &auditFields); err != nil {
		t.Fatal(err)
	}
	if auditFields["operator_owned_before"] != true || auditFields["operator_owned_after"] != false || auditFields["group_source_count"] != float64(2) || auditFields["effective_after"] != true {
		t.Fatalf("dishonest origin audit: %s", auditJSON)
	}
	plan, err = service.Preview(ctx, request)
	if err != nil || plan.Operation != "unchanged" {
		t.Fatalf("no operator revoke %+v %v", plan, err)
	}
	if result, err := service.Apply(ctx, request, plan.PlanID); err != nil || result.Changed {
		t.Fatalf("noop %+v %v", result, err)
	}
	assertOriginRow(t, db, false, 3, 2)
	var audits int
	if err := db.QueryRow("SELECT count(*) FROM audit_events").Scan(&audits); err != nil || audits != 2 {
		t.Fatalf("audit count %d %v", audits, err)
	}
}

func TestOperatorOriginPreviewAndStaleSources(t *testing.T) {
	db := roleDB(t)
	seedGroupOrigins(t, db, true)
	service := testService(db)
	request := scopedRequest()
	request.Operation = OperationRevoke
	plan, err := service.Preview(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(plan)
	var fields map[string]any
	_ = json.Unmarshal(raw, &fields)
	if fields["operator_owned"] != true || fields["group_source_count"] != float64(2) || fields["effective_after"] != false {
		t.Fatalf("missing/false origin disclosure: %s", raw)
	}
	if _, err := db.Exec("UPDATE identity_group_role_mappings SET revision=revision+1 WHERE id='00000000-0000-4000-8000-000000000921'"); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Apply(context.Background(), request, plan.PlanID); err == nil || !strings.Contains(err.Error(), "confirmation digest") {
		t.Fatalf("source drift accepted: %v", err)
	}
	assertOriginRow(t, db, true, 1, 2)
}

func TestOperatorOriginAuditRollback(t *testing.T) {
	db := roleDB(t)
	seedGroupOrigins(t, db, true)
	if _, err := db.Exec(`CREATE FUNCTION reject_origin_audit() RETURNS trigger AS $$ BEGIN RAISE EXCEPTION 'forced origin audit failure'; END; $$ LANGUAGE plpgsql; CREATE TRIGGER reject_origin_audit BEFORE INSERT ON audit_events FOR EACH ROW EXECUTE FUNCTION reject_origin_audit()`); err != nil {
		t.Fatal(err)
	}
	service := testService(db)
	request := scopedRequest()
	request.Operation = OperationRevoke
	plan, err := service.Preview(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Apply(context.Background(), request, plan.PlanID); err == nil {
		t.Fatal("audit failure admitted")
	}
	assertOriginRow(t, db, true, 1, 2)
}

func assertOriginRow(t *testing.T, db *sql.DB, owned bool, revision int64, sources int) {
	t.Helper()
	var id string
	var gotOwned bool
	var gotRevision int64
	var count int
	err := db.QueryRow("SELECT id::text,operator_owned,authority_revision,(SELECT count(*) FROM role_binding_group_sources WHERE binding_id=role_bindings.id) FROM role_bindings").Scan(&id, &gotOwned, &gotRevision, &count)
	if err != nil || id != groupBinding || gotOwned != owned || gotRevision != revision || count != sources {
		t.Fatalf("origin row id=%s owned=%v revision=%d sources=%d err=%v", id, gotOwned, gotRevision, count, err)
	}
}

func TestOperatorPlanEffectiveAfterAndVersion(t *testing.T) {
	request := scopedRequest()
	request.Operation = OperationRevoke
	base := state{identityID: testIdentity, mailbox: testMailbox, domainID: testDomain, bindingID: groupBinding, operatorOwned: true, authorityRevision: 1, mailboxEnabled: true, mailboxDomainEnabled: true, targetDomainEnabled: true, currentIssuer: testIssuer, sources: []groupSource{{ID: "one", Revision: 1, Issuer: testIssuer, Enabled: true, MatchesBinding: true}}}
	for _, tc := range []struct {
		name   string
		change func(*state)
		want   bool
	}{
		{"matching", func(*state) {}, true},
		{"mismatched binding", func(s *state) { s.sources[0].MatchesBinding = false }, false},
		{"missing issuer", func(s *state) { s.currentIssuer = "" }, false},
		{"wrong issuer", func(s *state) { s.currentIssuer = "https://other.test/" }, false},
		{"wrong mapping issuer", func(s *state) { s.sources[0].Issuer = "https://other.test/" }, false},
		{"disabled mapping", func(s *state) { s.sources[0].Enabled = false }, false},
		{"deleted mapping", func(s *state) { s.sources[0].Deleted = true }, false},
		{"mailbox disabled", func(s *state) { s.mailboxEnabled = false }, false},
		{"mailbox domain disabled", func(s *state) { s.mailboxDomainEnabled = false }, false},
		{"target domain disabled", func(s *state) { s.targetDomainEnabled = false }, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := base
			s.sources = append([]groupSource(nil), base.sources...)
			tc.change(&s)
			plan, err := buildPlan(request, s)
			if err != nil || plan.EffectiveAfter != tc.want {
				t.Fatalf("effective=%v want=%v err=%v", plan.EffectiveAfter, tc.want, err)
			}
		})
	}
	old := struct{ Schema, RequestedOperation, IdentityID, Mailbox, Role, Domain, DomainID, ExistingBindingID, ExistingBindingUpdated string }{"gotth-mail/role-binding-plan/v1", request.Operation, base.identityID, base.mailbox, request.Role, request.Domain, base.domainID, base.bindingID, base.bindingUpdated.UTC().Format(time.RFC3339Nano)}
	raw, err := json.Marshal(old)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	plan, err := buildPlan(request, base)
	if err != nil {
		t.Fatal(err)
	}
	if equalDigest(plan.PlanID, hex.EncodeToString(sum[:])) {
		t.Fatal("legacy v1 digest accepted")
	}
}
