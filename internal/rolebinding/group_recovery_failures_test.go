package rolebinding

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestGroupRecoveryCorruptionStaleAndAuditRollback(t *testing.T) {
	db := recoveryDB(t)
	s := GroupRecoveryService{DB: db}
	ctx := context.Background()
	groupExec(t, db, "ALTER TABLE identity_group_role_mappings DROP CONSTRAINT identity_group_role_mappings_role_check,DROP CONSTRAINT identity_group_role_mappings_check,DROP CONSTRAINT identity_group_role_mappings_revision_check,DROP CONSTRAINT identity_group_role_mappings_domain_id_fkey; ALTER TABLE role_binding_group_sources DROP CONSTRAINT role_binding_group_sources_binding_id_fkey,DROP CONSTRAINT role_binding_group_sources_mapping_id_fkey,DROP CONSTRAINT role_binding_group_sources_pkey")
	cases := []struct{ name, q, undo string }{
		{"issuer", "UPDATE identity_group_role_mappings SET issuer='https://user:password-canary@auth.example/application/o/gotth-mail/' WHERE id='00000000-0000-4000-8000-000000000901'", "UPDATE identity_group_role_mappings SET issuer='" + testIssuer + "' WHERE id='00000000-0000-4000-8000-000000000901'"},
		{"role", "UPDATE identity_group_role_mappings SET role='unknown' WHERE id='00000000-0000-4000-8000-000000000901'", "UPDATE identity_group_role_mappings SET role='global_admin' WHERE id='00000000-0000-4000-8000-000000000901'"},
		{"revision", "UPDATE identity_group_role_mappings SET revision=0 WHERE id='00000000-0000-4000-8000-000000000901'", "UPDATE identity_group_role_mappings SET revision=1 WHERE id='00000000-0000-4000-8000-000000000901'"},
		{"domain", "UPDATE identity_group_role_mappings SET domain_id='00000000-0000-4000-8000-000000000999' WHERE id='00000000-0000-4000-8000-000000000903'", "UPDATE identity_group_role_mappings SET domain_id='" + testDomain + "' WHERE id='00000000-0000-4000-8000-000000000903'"},
		{"orphan", "DELETE FROM role_binding_group_sources WHERE mapping_id='00000000-0000-4000-8000-000000000903'", "INSERT INTO role_binding_group_sources VALUES ('00000000-0000-4000-8000-000000000913','00000000-0000-4000-8000-000000000903')"},
		{"crossrole", "INSERT INTO role_binding_group_sources VALUES ('00000000-0000-4000-8000-000000000911','00000000-0000-4000-8000-000000000903')", "DELETE FROM role_binding_group_sources WHERE binding_id='00000000-0000-4000-8000-000000000911' AND mapping_id='00000000-0000-4000-8000-000000000903'"},
		{"missingbinding", "INSERT INTO role_binding_group_sources VALUES ('00000000-0000-4000-8000-000000000999','00000000-0000-4000-8000-000000000901')", "DELETE FROM role_binding_group_sources WHERE binding_id='00000000-0000-4000-8000-000000000999'"},
		{"missingmapping", "INSERT INTO role_binding_group_sources VALUES ('00000000-0000-4000-8000-000000000911','00000000-0000-4000-8000-000000000999')", "DELETE FROM role_binding_group_sources WHERE mapping_id='00000000-0000-4000-8000-000000000999'"},
		{"duplicate", "INSERT INTO role_binding_group_sources VALUES ('00000000-0000-4000-8000-000000000911','00000000-0000-4000-8000-000000000901')", "DELETE FROM role_binding_group_sources WHERE ctid IN (SELECT ctid FROM role_binding_group_sources WHERE mapping_id='00000000-0000-4000-8000-000000000901' LIMIT 1)"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p, e := s.Preview(ctx)
			if e != nil {
				t.Fatal(e)
			}
			groupExec(t, db, tc.q)
			before := groupSnapshot(t, db)
			_, pe := s.Preview(ctx)
			_, ae := s.Apply(ctx, p.PlanID)
			if pe == nil || ae == nil || before != groupSnapshot(t, db) {
				t.Fatal("corruption not rejected without writes", pe, ae)
			}
			groupExec(t, db, tc.undo)
		})
	}
	for _, tc := range []struct{ q, undo string }{
		{"DELETE FROM role_binding_group_sources WHERE mapping_id='00000000-0000-4000-8000-000000000901'", "INSERT INTO role_binding_group_sources VALUES ('00000000-0000-4000-8000-000000000911','00000000-0000-4000-8000-000000000901')"},
		{"UPDATE identity_group_role_mappings SET revision=revision+1 WHERE id='00000000-0000-4000-8000-000000000901'", "UPDATE identity_group_role_mappings SET revision=revision-1 WHERE id='00000000-0000-4000-8000-000000000901'"},
		{"UPDATE role_bindings SET authority_revision=authority_revision+1", "UPDATE role_bindings SET authority_revision=authority_revision-1"},
		{"UPDATE schema_migrations SET applied_at=applied_at+interval '1 second'", "UPDATE schema_migrations SET applied_at=applied_at-interval '1 second'"},
		{"INSERT INTO identity_group_role_mappings(id,issuer,scope,group_id,role,created_at,updated_at) VALUES ('00000000-0000-4000-8000-000000000999','" + testIssuer + "','new','absent','global_admin',now(),now())", "DELETE FROM identity_group_role_mappings WHERE id='00000000-0000-4000-8000-000000000999'"},
	} {
		p, e := s.Preview(ctx)
		if e != nil {
			t.Fatal(e)
		}
		groupExec(t, db, tc.q)
		before := groupSnapshot(t, db)
		if _, e = s.Apply(ctx, p.PlanID); e == nil || before != groupSnapshot(t, db) {
			t.Fatal("stale changed state", e)
		}
		groupExec(t, db, tc.undo)
	}
	for _, condition := range []string{"NEW.action='identity.group_role_mapping.disable' AND NEW.resource_id='00000000-0000-4000-8000-000000000903'", "NEW.action='identity.group_role_feature.disable'"} {
		groupExec(t, db, "CREATE OR REPLACE FUNCTION recovery_audit_fail() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN IF "+condition+" THEN RAISE EXCEPTION 'synthetic audit failure'; END IF;RETURN NEW;END$$; CREATE TRIGGER recovery_audit_failure BEFORE INSERT ON audit_events FOR EACH ROW EXECUTE FUNCTION recovery_audit_fail()")
		p, e := s.Preview(ctx)
		if e != nil {
			t.Fatal(e)
		}
		before := groupSnapshot(t, db)
		if _, e = s.Apply(ctx, p.PlanID); e == nil || before != groupSnapshot(t, db) {
			t.Fatal("audit failure not atomic", e)
		}
		groupExec(t, db, "DROP TRIGGER recovery_audit_failure ON audit_events")
	}
	groupExec(t, db, "CREATE OR REPLACE FUNCTION recovery_commit_fail() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN IF NEW.action='identity.group_role_feature.disable' THEN RAISE EXCEPTION 'deferred audit failure'; END IF;RETURN NEW;END$$; CREATE CONSTRAINT TRIGGER recovery_commit_failure AFTER INSERT ON audit_events DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION recovery_commit_fail()")
	p, e := s.Preview(ctx)
	if e != nil {
		t.Fatal(e)
	}
	before := groupSnapshot(t, db)
	if _, e = s.Apply(ctx, p.PlanID); e == nil || !strings.Contains(e.Error(), "commit outcome requires inspection") || before != groupSnapshot(t, db) {
		t.Fatal("deferred commit error", e)
	}
	groupExec(t, db, "DROP TRIGGER recovery_commit_failure ON audit_events; UPDATE domains SET enabled=false; UPDATE mailboxes SET enabled=false")
	p, e = s.Preview(ctx)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.Apply(ctx, p.PlanID); e != nil {
		t.Fatal("disabled metadata blocked recovery", e)
	}
	groupExec(t, db, "DELETE FROM role_bindings; DELETE FROM identity_group_role_mappings")
	p, e = s.Preview(ctx)
	if e != nil || p.ChangedMappings != 0 || len(p.Bindings) != 0 {
		t.Fatal("empty", p, e)
	}
	before = groupSnapshot(t, db)
	if _, e = s.Apply(ctx, p.PlanID); e != nil || before != groupSnapshot(t, db) {
		t.Fatal("empty wrote", e)
	}

}
func TestGroupRecoveryConcurrentChangingWinner(t *testing.T) {
	db := recoveryDB(t)
	s := GroupRecoveryService{DB: db}
	ctx := context.Background()
	p, e := s.Preview(ctx)
	if e != nil {
		t.Fatal(e)
	}
	start := make(chan struct{})
	var wg sync.WaitGroup
	var mu sync.Mutex
	wins := 0
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			v, e := s.Apply(ctx, p.PlanID)
			mu.Lock()
			defer mu.Unlock()
			if e == nil && v.Changed {
				wins++
			}
		}()
	}
	close(start)
	wg.Wait()
	if wins != 1 {
		t.Fatal("changing winners", wins)
	}
	groupCounts(t, db, 4, 1, 0, 10)
}
func TestGroupRecoveryDigestContextAndFailures(t *testing.T) {
	st := recoveryState{Database: "one", User: "maint", Mappings: []recoveryMapping{}, Bindings: []recoveryBinding{}, Sources: []recoverySource{}, Ledger: []recoveryLedger{}}
	p, e := planRecovery(st)
	if e != nil {
		t.Fatal(e)
	}
	st.Database = "two"
	q, e := planRecovery(st)
	if e != nil || p.PlanID == q.PlanID {
		t.Fatal("database context unbound", e)
	}
	st.User = "other"
	v, _ := planRecovery(st)
	if v.PlanID == q.PlanID {
		t.Fatal("user unbound")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Nanosecond)
	defer cancel()
	if _, e := (GroupRecoveryService{}).Preview(ctx); e == nil {
		t.Fatal("missing db")
	}
	if _, e := (GroupRecoveryService{}).Apply(ctx, strings.Repeat("0", 64)); e == nil {
		t.Fatal("missing db")
	}
}
