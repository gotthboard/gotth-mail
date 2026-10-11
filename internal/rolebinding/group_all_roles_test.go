package rolebinding

import (
	"context"
	"database/sql"
	"forgejo/gotthboard/gotth-mail/internal/audit"
	"forgejo/gotthboard/gotth-mail/internal/authn"
	"forgejo/gotthboard/gotth-mail/internal/authz"
	"forgejo/gotthboard/gotth-mail/internal/roleprojection"
	"testing"
	"time"
)

func TestGroupAllRolesIndependentOrigins(t *testing.T) {
	db := groupDB(t)
	s := GroupService{DB: db, CurrentIssuer: testIssuer}
	ctx := context.Background()
	roles := []string{RoleGlobalAdmin, RoleDomainManager, RoleScopedDomainAccess}
	ids := map[string]string{}
	for _, role := range roles {
		r := groupRequest()
		r.Role = role
		if role == RoleGlobalAdmin {
			r.Domain = ""
		}
		start := time.Now()
		v := groupApply(t, s, r)
		if v.Plan.AddedSources != 1 || !v.Plan.FutureMemberDelegation || !v.Plan.EffectiveAfter {
			t.Fatal(v)
		}
		t.Logf("role=%s I=1 M=1 preview+apply=%s", role, time.Since(start))
		var id string
		var owned bool
		if e := db.QueryRow("SELECT id::text,operator_owned FROM role_bindings WHERE role=$1", role).Scan(&id, &owned); e != nil || owned {
			t.Fatal(id, owned, e)
		}
		ids[role] = id
		r.GroupID = "g2"
		groupApply(t, s, r)
		op := scopedRequest()
		op.Role = role
		op.Domain = r.Domain
		os := Service{DB: db, CurrentIssuer: testIssuer}
		p, e := os.Preview(ctx, op)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = os.Apply(ctx, op, p.PlanID); e != nil {
			t.Fatal(e)
		}
	}
	groupCounts(t, db, 6, 3, 6, 15)
	var badAudits int
	if e := db.QueryRow("SELECT count(*) FROM audit_events a JOIN role_bindings rb ON rb.id::text=a.resource_id WHERE a.action LIKE 'identity.group_role_source.%' AND a.after_redacted_json::jsonb->>'role'<>rb.role").Scan(&badAudits); e != nil || badAudits != 0 {
		t.Fatal("wrong audit role", badAudits, e)
	}
	groupExec(t, db, "CREATE FUNCTION deny_all_role_noop() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'noop DML'; END$$")
	for _, table := range []string{"identity_group_role_mappings", "role_bindings", "role_binding_group_sources", "audit_events"} {
		groupExec(t, db, "CREATE TRIGGER deny_all_role_noop BEFORE INSERT OR UPDATE OR DELETE ON "+table+" FOR EACH STATEMENT EXECUTE FUNCTION deny_all_role_noop()")
	}
	for _, role := range roles {
		r := groupRequest()
		r.Role = role
		if role == RoleGlobalAdmin {
			r.Domain = ""
		}
		v := groupApply(t, s, r)
		if v.Changed {
			t.Fatal("noop changed")
		}
	}
	for _, table := range []string{"identity_group_role_mappings", "role_bindings", "role_binding_group_sources", "audit_events"} {
		groupExec(t, db, "DROP TRIGGER deny_all_role_noop ON "+table)
	}
	bound, ok := (authn.SQLStore{DB: db, CurrentIssuer: testIssuer}).BoundSession(ctx, "existing-session", time.Now())
	if !ok || len(bound.Roles) != 3 {
		t.Fatal(bound, ok)
	}
	for _, role := range roles {
		r := groupRequest()
		r.Role = role
		r.Operation = "disable"
		if role == RoleGlobalAdmin {
			r.Domain = ""
		}
		v := groupApply(t, s, r)
		if !v.Plan.EffectiveAfter {
			t.Fatal(v)
		}
		var same string
		db.QueryRow("SELECT id::text FROM role_bindings WHERE role=$1", role).Scan(&same)
		if same != ids[role] {
			t.Fatal("UUID replaced")
		}
		op := scopedRequest()
		op.Role = role
		op.Domain = r.Domain
		op.Operation = OperationRevoke
		os := Service{DB: db, CurrentIssuer: testIssuer}
		p, e := os.Preview(ctx, op)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = os.Apply(ctx, op, p.PlanID); e != nil {
			t.Fatal(e)
		}
		r.GroupID = "g2"
		groupApply(t, s, r)
	}
	groupCounts(t, db, 6, 0, 0, 30)
	for _, role := range roles {
		r := groupRequest()
		r.Role = role
		if role == RoleGlobalAdmin {
			r.Domain = ""
		}
		groupApply(t, s, r)
	}
	for _, q := range []string{"UPDATE mailboxes SET enabled=false", "UPDATE domains SET enabled=false"} {
		groupExec(t, db, q)
		b, ok := (authn.SQLStore{DB: db, CurrentIssuer: testIssuer}).BoundSession(ctx, "existing-session", time.Now())
		if ok && len(b.Roles) != 0 {
			t.Fatal("local guard bypass", b)
		}
		groupExec(t, db, "UPDATE mailboxes SET enabled=true; UPDATE domains SET enabled=true")
	}
	for _, role := range []authz.Role{authz.RoleGlobalAdmin, authz.RoleDomainManager, authz.RoleScopedDomainAccess} {
		domain := "example.test"
		if role == authz.RoleGlobalAdmin {
			domain = ""
		}
		a := authz.Actor{Type: "oidc_subject", Roles: []authz.RoleAssignment{{Role: role, Domain: domain}}}
		for _, tc := range []struct {
			action string
			domain string
			want   bool
		}{{"domain:read", "example.test", true}, {"domain:write", "example.test", role != authz.RoleScopedDomainAccess}, {"domain:write", "other.test", role == authz.RoleGlobalAdmin}} {
			d, e := (authz.StaticAuthorizer{}).Decide(ctx, a, authz.Action(tc.action), authz.Resource{Type: "domain", ID: tc.domain})
			if e != nil || d.Allow != tc.want {
				t.Fatal(role, tc, d, e)
			}
		}
	}
}
func TestGroupAllRolesShapesAndFullDiff(t *testing.T) {
	db := groupDB(t)
	s := GroupService{DB: db, CurrentIssuer: testIssuer}
	ctx := context.Background()
	for _, tc := range []struct{ role, domain string }{{"unknown", "example.test"}, {RoleGlobalAdmin, "example.test"}, {RoleDomainManager, ""}, {RoleScopedDomainAccess, ""}} {
		r := groupRequest()
		r.Role = tc.role
		r.Domain = tc.domain
		before := groupSnapshot(t, db)
		if _, e := s.Preview(ctx, r); e == nil {
			t.Fatal("shape accepted", tc)
		}
		if before != groupSnapshot(t, db) {
			t.Fatal("denial wrote")
		}
	}
	groupExec(t, db, "INSERT INTO domains(id,name,enabled,created_at,updated_at) VALUES ('00000000-0000-4000-8000-000000000999','other.test',true,now(),now())")
	for _, role := range []string{RoleDomainManager, RoleScopedDomainAccess} {
		for _, domain := range []string{"example.test", "other.test"} {
			r := groupRequest()
			r.Role = role
			r.Domain = domain
			groupApply(t, s, r)
		}
	}
	r := groupRequest()
	r.Role = RoleGlobalAdmin
	r.Domain = ""
	p, e := s.Preview(ctx, r)
	if e != nil || len(p.Impacts) != 5 || p.AddedSources != 1 {
		t.Fatal(p, e)
	}
	groupApply(t, s, r)
	groupCounts(t, db, 5, 5, 5, 10)
	before := groupSnapshot(t, db)
	v := groupApply(t, s, r)
	if v.Changed || before != groupSnapshot(t, db) {
		t.Fatal("noop wrote")
	}
	r.Operation = "disable"
	p, e = s.Preview(ctx, r)
	if e != nil {
		t.Fatal(e)
	}
	groupExec(t, db, "UPDATE role_bindings SET authority_revision=authority_revision+1 WHERE role='scoped_domain_access'")
	before = groupSnapshot(t, db)
	if _, e = s.Apply(ctx, r, p.PlanID); e == nil || before != groupSnapshot(t, db) {
		t.Fatal("cross-role stale accepted")
	}
}

func TestGroupAllRolesAtomicRecoveryAndRace(t *testing.T) {
	db := groupDB(t)
	s := GroupService{DB: db, CurrentIssuer: testIssuer}
	ctx := context.Background()
	for _, role := range []string{RoleGlobalAdmin, RoleScopedDomainAccess} {
		t.Run(role, func(t *testing.T) {
			r := groupRequest()
			r.Role = role
			if role == RoleGlobalAdmin {
				r.Domain = ""
			}
			for _, operation := range []string{"admit", "disable"} {
				r.Operation = operation
				p, e := s.Preview(ctx, r)
				if e != nil {
					t.Fatal(e)
				}
				groupExec(t, db, "CREATE OR REPLACE FUNCTION fail_all_role_audit() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN IF NEW.action LIKE 'identity.group_role_mapping.%' THEN RAISE EXCEPTION 'late role audit'; END IF; RETURN NEW; END$$; CREATE TRIGGER fail_all_role_audit BEFORE INSERT ON audit_events FOR EACH ROW EXECUTE FUNCTION fail_all_role_audit()")
				before := groupSnapshot(t, db)
				if _, e = s.Apply(ctx, r, p.PlanID); e == nil {
					t.Fatal("audit admitted")
				}
				if groupSnapshot(t, db) != before {
					t.Fatal("atomic rollback leaked")
				}
				groupExec(t, db, "DROP TRIGGER fail_all_role_audit ON audit_events")
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
					t.Fatal("race winners", wins)
				}
			}
			r.Operation = "admit"
			groupApply(t, s, r)
		})
	}
	groupExec(t, db, "UPDATE scim_resources SET data=convert_to('malformed','UTF8') WHERE id='u'; DELETE FROM scim_resources WHERE id='g1'; UPDATE domains SET enabled=false")
	s.CurrentIssuer = ""
	for _, role := range []string{RoleGlobalAdmin, RoleScopedDomainAccess} {
		r := groupRequest()
		r.Role = role
		r.Operation = "disable"
		if role == RoleGlobalAdmin {
			r.Domain = ""
		}
		groupApply(t, s, r)
		before := groupSnapshot(t, db)
		v := groupApply(t, s, r)
		if v.Changed || before != groupSnapshot(t, db) {
			t.Fatal("recovery noop wrote")
		}
	}
	groupCounts(t, db, 2, 0, 0, 16)
}

func TestGroupAllRolesWholeProjectionAndGuards(t *testing.T) {
	db := groupDB(t)
	s := GroupService{DB: db, CurrentIssuer: testIssuer}
	ctx := context.Background()
	r := groupRequest()
	for _, role := range []string{RoleGlobalAdmin, RoleDomainManager, RoleScopedDomainAccess} {
		r.Role = role
		r.Domain = "example.test"
		if role == RoleGlobalAdmin {
			r.Domain = ""
		}
		groupApply(t, s, r)
	}
	groupExec(t, db, "DELETE FROM scim_group_members WHERE group_id='g1'")
	r = groupRequest()
	r.GroupID = "g2"
	r.Role = RoleGlobalAdmin
	r.Domain = ""
	p, e := s.Preview(ctx, r)
	if e != nil || p.RemovedSources != 3 || p.AddedSources != 1 || len(p.Impacts) != 3 {
		t.Fatal("preview not whole-role diff", p, e)
	}
	for _, impact := range p.Impacts {
		if impact.EffectiveAfter != (impact.Role == RoleGlobalAdmin) {
			t.Fatal("whole-role effect incorrect", impact)
		}
	}
	var globalID string
	if e = db.QueryRow("SELECT id::text FROM role_bindings WHERE role='global_admin'").Scan(&globalID); e != nil {
		t.Fatal(e)
	}
	if _, e = s.Apply(ctx, r, p.PlanID); e != nil {
		t.Fatal(e)
	}
	groupCounts(t, db, 4, 1, 1, 11)
	var same string
	db.QueryRow("SELECT id::text FROM role_bindings").Scan(&same)
	if same != globalID {
		t.Fatal("source swap global UUID")
	}
	for _, role := range []string{RoleDomainManager, RoleScopedDomainAccess} {
		r.Role = role
		r.Domain = "example.test"
		groupApply(t, s, r)
	}
	project := func(issuer string) {
		t.Helper()
		tx, e := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
		if e != nil {
			t.Fatal(e)
		}
		defer tx.Rollback()
		if e = (roleprojection.Projector{CurrentIssuer: issuer, Actor: audit.ActorRef{Type: "local_admin", ID: "test"}}).SyncIdentity(ctx, tx, testIdentity); e != nil {
			t.Fatal(e)
		}
		if e = tx.Commit(); e != nil {
			t.Fatal(e)
		}
	}
	for _, tc := range []struct{ q, restore string }{{"UPDATE identity_refs SET provider='local'", "UPDATE identity_refs SET provider='authentik'"}, {"UPDATE scim_resources SET external_id='wrong-subject' WHERE id='u'", "UPDATE scim_resources SET external_id='" + testSubject + "' WHERE id='u'"}, {"UPDATE mailboxes SET scim_resource_id=NULL", "UPDATE mailboxes SET scim_resource_id='u'"}, {"UPDATE scim_resources SET data=convert_to('{\"active\":false}','UTF8') WHERE id='u'", "UPDATE scim_resources SET data=convert_to('{\"active\":true}','UTF8') WHERE id='u'"}} {
		groupExec(t, db, tc.q)
		project(testIssuer)
		var n int
		db.QueryRow("SELECT count(*) FROM role_bindings").Scan(&n)
		if n != 0 {
			t.Fatal("allrole exact predicate bypass")
		}
		groupExec(t, db, tc.restore)
		project("")
		db.QueryRow("SELECT count(*) FROM role_bindings").Scan(&n)
		if n != 0 {
			t.Fatal("missing issuer added")
		}
		project(testIssuer)
		db.QueryRow("SELECT count(*) FROM role_bindings").Scan(&n)
		if n != 3 {
			t.Fatal("allrole recovery missing", n)
		}
	}
	before := groupSnapshot(t, db)
	project("https://other.example/application/o/gotth-mail/")
	if before != groupSnapshot(t, db) {
		t.Fatal("issuer change retracted structural origins")
	}
	b, ok := (authn.SQLStore{DB: db, CurrentIssuer: "https://other.example/application/o/gotth-mail/"}).BoundSession(ctx, "existing-session", time.Now())
	if !ok || len(b.Roles) != 0 {
		t.Fatal("issuer read bypass", b, ok)
	}
}
