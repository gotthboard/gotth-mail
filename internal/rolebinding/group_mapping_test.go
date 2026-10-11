package rolebinding

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"forgejo/gotthboard/gotth-mail/internal/authn"
	"forgejo/gotthboard/gotth-mail/internal/identityruntime"
	"strings"
	"testing"
	"time"
)

func groupDB(t *testing.T) *sql.DB {
	t.Helper()
	db := roleDB(t)
	scope := identityruntime.Scope("scim-actor")
	groupExec(t, db, "INSERT INTO scim_resources(scope,resource_type,id,external_id,version,created_unix_nano,last_modified_unix_nano,data) VALUES ($1,'User','u',$2,'v1',1,1,$3)", scope, testSubject, []byte(`{"active":true}`))
	groupExec(t, db, "UPDATE mailboxes SET scim_resource_id='u'")
	for _, g := range []string{"g1", "g2"} {
		groupExec(t, db, "INSERT INTO scim_resources(scope,resource_type,id,version,created_unix_nano,last_modified_unix_nano,data) VALUES ($1,'Group',$2,'v1',1,1,$3)", scope, g, []byte(`{"members":[{"value":"u"}]}`))
		groupExec(t, db, "INSERT INTO scim_group_members(scope,group_id,user_id) VALUES ($1,$2,'u')", scope, g)
	}
	return db
}
func groupExec(t *testing.T, db *sql.DB, q string, args ...any) {
	t.Helper()
	if _, e := db.Exec(q, args...); e != nil {
		t.Fatal(e)
	}
}
func groupRequest() GroupRequest {
	return GroupRequest{Operation: "admit", Issuer: testIssuer, SCIMActor: "scim-actor", GroupID: "g1", Role: "domain_manager", Domain: "example.test"}
}
func groupSnapshot(t *testing.T, db *sql.DB) string {
	t.Helper()
	var out strings.Builder
	for _, table := range []string{"domains", "mailboxes", "identity_refs", "sessions", "scim_resources", "scim_group_members", "scim_tombstones", "identity_group_role_mappings", "role_bindings", "role_binding_group_sources", "audit_events"} {
		var s string
		if e := db.QueryRow("SELECT COALESCE(jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text),'[]')::text FROM " + table + " t").Scan(&s); e != nil {
			t.Fatal(e)
		}
		out.WriteString(table + s)
	}
	return out.String()
}
func groupCounts(t *testing.T, db *sql.DB, m, b, s, a int) {
	t.Helper()
	for table, want := range map[string]int{"identity_group_role_mappings": m, "role_bindings": b, "role_binding_group_sources": s, "audit_events": a} {
		var n int
		if e := db.QueryRow("SELECT count(*) FROM " + table).Scan(&n); e != nil || n != want {
			t.Fatalf("%s=%d want=%d err=%v", table, n, want, e)
		}
	}
}
func groupApply(t *testing.T, s GroupService, r GroupRequest) GroupResult {
	t.Helper()
	p, e := s.Preview(context.Background(), r)
	if e != nil {
		t.Fatal(e)
	}
	v, e := s.Apply(context.Background(), r, p.PlanID)
	if e != nil {
		t.Fatal(e)
	}
	return v
}
func TestGroupMappingLifecycleAndNoop(t *testing.T) {
	db := groupDB(t)
	s := GroupService{DB: db, CurrentIssuer: testIssuer}
	r := groupRequest()
	ctx := context.Background()
	before := groupSnapshot(t, db)
	start := time.Now()
	p, e := s.Preview(ctx, r)
	if e != nil {
		t.Fatal(e)
	}
	t.Logf("Preview M=1 I=1 B=one-small-User elapsed=%s", time.Since(start))
	if groupSnapshot(t, db) != before || p.Operation != "admit" || !p.FutureMemberDelegation || p.AddedSources != 1 || len(p.Impacts) != 1 || !p.Impacts[0].EffectiveAfter {
		t.Fatalf("preview=%+v", p)
	}
	raw, _ := json.Marshal(p)
	if p.GroupID != r.GroupID || p.Scope != identityruntime.Scope(r.SCIMActor) {
		t.Fatal("preview hides exact Group/scope target", p)
	}
	for _, secret := range []string{testSubject, testIssuer, "scim-actor", "active"} {
		if strings.Contains(string(raw), secret) {
			t.Fatalf("preview leaks %s: %s", secret, raw)
		}
	}
	result, e := s.Apply(ctx, r, p.PlanID)
	if e != nil || !result.Changed {
		t.Fatal(result, e)
	}
	groupCounts(t, db, 1, 1, 1, 2)
	var id string
	var owned bool
	if e = db.QueryRow("SELECT id::text,operator_owned FROM role_bindings").Scan(&id, &owned); e != nil || owned {
		t.Fatal(id, owned, e)
	}
	bound, ok := (authn.SQLStore{DB: db, CurrentIssuer: testIssuer}).BoundSession(ctx, "existing-session", time.Now())
	if !ok || len(bound.Roles) != 1 {
		t.Fatal("grant missing", bound, ok)
	}
	groupExec(t, db, "CREATE FUNCTION deny_group_write() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'no-op wrote'; END$$")
	for _, table := range []string{"identity_group_role_mappings", "role_bindings", "role_binding_group_sources", "audit_events"} {
		groupExec(t, db, "CREATE TRIGGER no_write BEFORE INSERT OR UPDATE OR DELETE ON "+table+" FOR EACH STATEMENT EXECUTE FUNCTION deny_group_write()")
	}
	before = groupSnapshot(t, db)
	result = groupApply(t, s, r)
	if result.Changed || result.Plan.Operation != "unchanged" || groupSnapshot(t, db) != before {
		t.Fatal("no-op changed state", result)
	}
	for _, table := range []string{"identity_group_role_mappings", "role_bindings", "role_binding_group_sources", "audit_events"} {
		groupExec(t, db, "DROP TRIGGER no_write ON "+table)
	}
	op := Service{DB: db, CurrentIssuer: testIssuer}
	or := scopedRequest()
	opPlan, e := op.Preview(ctx, or)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = op.Apply(ctx, or, opPlan.PlanID); e != nil {
		t.Fatal(e)
	}
	r.GroupID = "g2"
	groupApply(t, s, r)
	groupCounts(t, db, 2, 1, 2, 5)
	r.GroupID = "g1"
	r.Operation = "disable"
	s.CurrentIssuer = "https://other.example/application/o/gotth-mail/"
	groupExec(t, db, "UPDATE domains SET enabled=false")
	result = groupApply(t, s, r)
	if !result.Plan.Impacts[0].EffectiveAfter || result.Plan.Impacts[0].SourcesAfter != 1 {
		t.Fatal("remaining origin falsely revoked", result)
	}
	groupCounts(t, db, 2, 1, 1, 7)
	r.GroupID = "g2"
	s.CurrentIssuer = ""
	groupExec(t, db, "DELETE FROM scim_resources WHERE id='g2'")
	groupApply(t, s, r)
	groupCounts(t, db, 2, 1, 0, 9)
	var same string
	if e = db.QueryRow("SELECT id::text FROM role_bindings").Scan(&same); e != nil || same != id {
		t.Fatal("operator UUID lost", same, e)
	}
	r = groupRequest()
	s.CurrentIssuer = testIssuer
	groupExec(t, db, "UPDATE domains SET enabled=true")
	groupApply(t, s, r)
	groupCounts(t, db, 2, 1, 1, 11)
	var revision int
	if e = db.QueryRow("SELECT revision FROM identity_group_role_mappings WHERE group_id='g1'").Scan(&revision); e != nil || revision != 3 {
		t.Fatal("mapping revision", revision, e)
	}
}
func TestGroupMappingFutureDelegationAndDenials(t *testing.T) {
	db := groupDB(t)
	s := GroupService{DB: db, CurrentIssuer: testIssuer}
	r := groupRequest()
	ctx := context.Background()
	for _, change := range []func(*GroupRequest, *GroupService){func(r *GroupRequest, s *GroupService) { s.CurrentIssuer = "" }, func(r *GroupRequest, s *GroupService) {
		s.CurrentIssuer = "https://other.example/application/o/gotth-mail/"
	}, func(r *GroupRequest, s *GroupService) { s.CurrentIssuer = "garbage" }, func(r *GroupRequest, s *GroupService) { r.SCIMActor = "foreign" }, func(r *GroupRequest, s *GroupService) { r.GroupID = "u" }, func(r *GroupRequest, s *GroupService) { r.GroupID = "unknown" }, func(r *GroupRequest, s *GroupService) { r.Domain = "unknown.test" }, func(r *GroupRequest, s *GroupService) { r.Role = "global_admin" }, func(r *GroupRequest, s *GroupService) { r.Issuer = "" }, func(r *GroupRequest, s *GroupService) { r.SCIMActor = "bad\nactor" }} {
		q, service := r, s
		change(&q, &service)
		if _, e := service.Preview(ctx, q); e == nil {
			t.Fatalf("invalid authority accepted %+v", q)
		}
	}
	groupExec(t, db, "UPDATE domains SET enabled=false")
	if _, e := s.Preview(ctx, r); e == nil {
		t.Fatal("disabled target admitted")
	}
	groupExec(t, db, "UPDATE domains SET enabled=true; DELETE FROM sessions; DELETE FROM identity_refs")
	p, e := s.Preview(ctx, r)
	if e != nil || !p.FutureMemberDelegation || p.MemberCount != 1 || p.AddedSources != 0 || len(p.Impacts) != 0 {
		t.Fatal(p, e)
	}
	groupApply(t, s, r)
	groupCounts(t, db, 1, 0, 0, 1)
	groupExec(t, db, "UPDATE identity_group_role_mappings SET enabled=false,group_deleted=true")
	if _, e = s.Preview(ctx, r); e == nil {
		t.Fatal("tombstoned tuple rebound")
	}
	r.Operation = "disable"
	s.CurrentIssuer = ""
	groupApply(t, s, r)
	groupCounts(t, db, 1, 0, 0, 1)
	r.GroupID = "missing"
	r.Domain = "missing.test"
	groupApply(t, s, r)
	groupCounts(t, db, 1, 0, 0, 1)
}
func TestGroupMappingStaleInputsAndAtomicAudit(t *testing.T) {
	db := groupDB(t)
	s := GroupService{DB: db, CurrentIssuer: testIssuer}
	r := groupRequest()
	ctx := context.Background()
	cases := []struct{ q, restore string }{
		{"UPDATE scim_resources SET version='v2' WHERE id='g1'", "UPDATE scim_resources SET version='v1' WHERE id='g1'"},
		{"DELETE FROM scim_group_members WHERE group_id='g1'", "INSERT INTO scim_group_members(scope,group_id,user_id) SELECT scope,'g1','u' FROM scim_resources WHERE id='u'"},
		{"UPDATE scim_resources SET data=convert_to('{\"active\":false}','UTF8') WHERE id='u'", "UPDATE scim_resources SET data=convert_to('{\"active\":true}','UTF8') WHERE id='u'"},
		{"UPDATE identity_refs SET subject='different'", "UPDATE identity_refs SET subject='" + testSubject + "'"},
		{"UPDATE mailboxes SET enabled=false", "UPDATE mailboxes SET enabled=true"},
		{"UPDATE domains SET enabled=false", "UPDATE domains SET enabled=true"},
	}
	for i, c := range cases {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			p, e := s.Preview(ctx, r)
			if e != nil {
				t.Fatal(e)
			}
			groupExec(t, db, c.q)
			before := groupSnapshot(t, db)
			if _, e = s.Apply(ctx, r, p.PlanID); e == nil {
				t.Fatal("stale plan accepted")
			}
			if groupSnapshot(t, db) != before {
				t.Fatal("stale apply wrote")
			}
			groupExec(t, db, c.restore)
		})
	}
	p, e := s.Preview(ctx, r)
	if e != nil {
		t.Fatal(e)
	}
	other := s
	other.CurrentIssuer = ""
	if _, e = other.Apply(ctx, r, p.PlanID); e == nil {
		t.Fatal("changed authority accepted")
	}
	for _, confirm := range []string{"", "wrong", strings.Repeat("0", 64)} {
		if _, e = s.Apply(ctx, r, confirm); e == nil {
			t.Fatal("invalid digest accepted")
		}
	}
	before := groupSnapshot(t, db)
	groupExec(t, db, "CREATE FUNCTION reject_mapping_audit() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN IF NEW.action LIKE 'identity.group_role_mapping.%' THEN RAISE EXCEPTION 'mapping audit failure'; END IF; RETURN NEW; END$$; CREATE TRIGGER reject_mapping_audit BEFORE INSERT ON audit_events FOR EACH ROW EXECUTE FUNCTION reject_mapping_audit()")
	if _, e = s.Apply(ctx, r, p.PlanID); e == nil {
		t.Fatal("mapping audit failure accepted")
	}
	if groupSnapshot(t, db) != before {
		t.Fatal("mapping audit leaked mapping/origin/binding/audit")
	}
}
func TestGroupMappingAbsentTupleRace(t *testing.T) {
	db := groupDB(t)
	s := GroupService{DB: db, CurrentIssuer: testIssuer}
	r := groupRequest()
	ctx := context.Background()
	for _, operation := range []string{"admit", "disable"} {
		r.Operation = operation
		p, e := s.Preview(ctx, r)
		if e != nil {
			t.Fatal(e)
		}
		start := make(chan struct{})
		done := make(chan error, 2)
		for range 2 {
			go func() { <-start; _, e := s.Apply(ctx, r, p.PlanID); done <- e }()
		}
		close(start)
		wins := 0
		for range 2 {
			if <-done == nil {
				wins++
			}
		}
		if wins != 1 {
			t.Fatalf("%s winners=%d", operation, wins)
		}
	}
	groupCounts(t, db, 1, 0, 0, 4)
}

func TestGroupMappingRetiredGroupCannotRebindTuple(t *testing.T) {
	db := groupDB(t)
	s := GroupService{DB: db, CurrentIssuer: testIssuer}
	r := groupRequest()
	groupApply(t, s, r)
	groupExec(t, db, "UPDATE identity_group_role_mappings SET enabled=false,group_deleted=true")
	groupExec(t, db, "INSERT INTO domains(id,name,enabled,created_at,updated_at) VALUES ('00000000-0000-4000-8000-000000000999','other.test',true,now(),now())")
	for _, which := range []string{"domain", "issuer"} {
		t.Run(which, func(t *testing.T) {
			q, service := r, s
			if which == "domain" {
				q.Domain = "other.test"
			} else {
				q.Issuer = "https://other.example/application/o/gotth-mail/"
				service.CurrentIssuer = q.Issuer
			}
			if _, e := service.Preview(context.Background(), q); e == nil {
				t.Fatal("retired opaque Group reused through changed tuple")
			}
		})
	}
}
func TestGroupMappingProvenanceStalenessAndRecovery(t *testing.T) {
	db := groupDB(t)
	s := GroupService{DB: db, CurrentIssuer: testIssuer}
	r := groupRequest()
	groupApply(t, s, r)
	r.Operation = "disable"
	ctx := context.Background()
	for _, q := range []string{"UPDATE identity_group_role_mappings SET revision=revision+1", "UPDATE role_bindings SET authority_revision=authority_revision+1", "UPDATE role_bindings SET operator_owned=true", "UPDATE scim_resources SET external_id='different' WHERE id='u'"} {
		p, e := s.Preview(ctx, r)
		if e != nil {
			t.Fatal(e)
		}
		groupExec(t, db, q)
		before := groupSnapshot(t, db)
		if _, e = s.Apply(ctx, r, p.PlanID); e == nil {
			t.Fatal("provenance stale digest accepted")
		}
		if groupSnapshot(t, db) != before {
			t.Fatal("stale provenance apply wrote")
		}
	}
	groupExec(t, db, "UPDATE scim_resources SET data=convert_to('invalid JSON','UTF8') WHERE id='u'; DELETE FROM scim_resources WHERE id='g1'; UPDATE domains SET enabled=false")
	s.CurrentIssuer = ""
	result := groupApply(t, s, r)
	if !result.Changed || !result.Plan.EffectiveAfter {
		t.Fatal("recovery lost independent operator origin", result)
	}
	groupCounts(t, db, 1, 1, 0, 4)
}

func TestGroupMappingRecoveryAuditAndSchemaGuards(t *testing.T) {
	db := groupDB(t)
	s := GroupService{DB: db, CurrentIssuer: testIssuer}
	r := groupRequest()
	ctx := context.Background()
	tx, e := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if e != nil {
		t.Fatal(e)
	}
	st, e := loadGroupState(ctx, tx, r, testIssuer)
	if e != nil {
		t.Fatal(e)
	}
	tx.Rollback()
	raw, e := json.Marshal(struct {
		Schema, Authority string
		Request           GroupRequest
		State             groupState
	}{"gotth-mail/group-role-plan/v1", testIssuer, r, st})
	if e != nil {
		t.Fatal(e)
	}
	sum := sha256.Sum256(raw)
	before := groupSnapshot(t, db)
	if _, e = s.Apply(ctx, r, hex.EncodeToString(sum[:])); e == nil {
		t.Fatal("old schema confirmation admitted")
	}
	if groupSnapshot(t, db) != before {
		t.Fatal("old-schema apply wrote")
	}
	groupExec(t, db, "CREATE FUNCTION require_mapping_serializable() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN IF current_setting('transaction_isolation') <> 'serializable' THEN RAISE EXCEPTION 'mapping mutation not serializable'; END IF; RETURN NEW; END$$; CREATE TRIGGER mapping_isolation BEFORE INSERT OR UPDATE ON identity_group_role_mappings FOR EACH ROW EXECUTE FUNCTION require_mapping_serializable()")
	groupApply(t, s, r)
	for _, action := range []string{"identity.group_role_mapping.disable", "identity.group_role_source.remove", "identity.group_role_source.add"} {
		groupExec(t, db, "CREATE OR REPLACE FUNCTION fail_group_boundary() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN IF NEW.action='"+action+"' THEN RAISE EXCEPTION 'group boundary audit failure'; END IF; RETURN NEW; END$$; CREATE TRIGGER fail_group_boundary BEFORE INSERT ON audit_events FOR EACH ROW EXECUTE FUNCTION fail_group_boundary()")
		q := r
		q.Operation = "disable"
		if action == "identity.group_role_source.add" {
			q.Operation = "admit"
			q.GroupID = "g2"
		}
		p, e := s.Preview(ctx, q)
		if e != nil {
			t.Fatal(e)
		}
		before = groupSnapshot(t, db)
		if _, e = s.Apply(ctx, q, p.PlanID); e == nil {
			t.Fatal("boundary audit failure admitted", action)
		}
		if groupSnapshot(t, db) != before {
			t.Fatal("audit failure leaked state", action)
		}
		groupExec(t, db, "DROP TRIGGER fail_group_boundary ON audit_events")
	}
	groupExec(t, db, "DELETE FROM scim_group_members WHERE group_id='g1'; UPDATE scim_resources SET data=convert_to('invalid JSON','UTF8') WHERE id='u'")
	before = groupSnapshot(t, db)
	result := groupApply(t, s, r)
	if result.Changed || result.Plan.AddedSources != 0 || result.Plan.RemovedSources != 0 || groupSnapshot(t, db) != before {
		t.Fatal("no-op opportunistically reconciled stale membership", result)
	}
}
func TestGroupMappingBoundedMemberScaling(t *testing.T) {
	db := groupDB(t)
	s := GroupService{DB: db, CurrentIssuer: testIssuer}
	r := groupRequest()
	last := 1
	for _, n := range []int{1, 8, 32} {
		if n > last {
			groupExec(t, db, `INSERT INTO scim_resources(scope,resource_type,id,external_id,version,created_unix_nano,last_modified_unix_nano,data) SELECT $1,'User','scale-user-'||i,'scale-subject-'||i,'v1',1,1,convert_to('{"active":true}','UTF8') FROM generate_series($2::int,$3::int) i`, identityruntime.Scope(r.SCIMActor), last+1, n)
			groupExec(t, db, "INSERT INTO scim_group_members(scope,group_id,user_id) SELECT $1,'g1','scale-user-'||i FROM generate_series($2::int,$3::int) i", identityruntime.Scope(r.SCIMActor), last+1, n)
		}
		last = n
		before := groupSnapshot(t, db)
		start := time.Now()
		p, e := s.Preview(context.Background(), r)
		elapsed := time.Since(start)
		if e != nil || p.MemberCount != n || p.AddedSources != 1 || len(p.Impacts) != 1 {
			t.Fatal(p, e)
		}
		if groupSnapshot(t, db) != before {
			t.Fatal("scaling preview wrote")
		}
		t.Logf("bounded native preview M=%d I=1 existingBindings=0 smallUserBytes=15 operation=%s; single sample, not matched performance/SLO", n, elapsed)
	}
	groupApply(t, s, r)
	groupCounts(t, db, 1, 1, 1, 2)
}
