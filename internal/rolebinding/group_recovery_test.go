package rolebinding

import (
	"context"
	"database/sql"
	"fmt"
	"forgejo/gotthboard/gotth-mail/internal/audit"
	"strings"
	"testing"
	"time"
)

func recoveryDB(t *testing.T) *sql.DB {
	t.Helper()
	db := groupDB(t)
	if e := audit.WriteSQL(context.Background(), db, audit.Event{Actor: audit.ActorRef{Type: "local_admin", ID: "fixture-history"}, Action: "fixture.history", Resource: audit.ResourceRef{Type: "identity", ID: testIdentity}, Result: "success"}); e != nil {
		t.Fatal(e)
	}
	for i, role := range []string{RoleGlobalAdmin, RoleGlobalAdmin, RoleDomainManager, RoleScopedDomainAccess} {
		var domain any
		if i > 1 {
			domain = testDomain
		}
		issuer := testIssuer
		if i == 1 {
			issuer = "https://old.example/application/o/gotth-mail/"
		}
		groupExec(t, db, "INSERT INTO identity_group_role_mappings(id,issuer,scope,group_id,role,domain_id,enabled,group_deleted,created_at,updated_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,now(),now())", fmt.Sprintf("00000000-0000-4000-8000-%012d", 901+i), issuer, fmt.Sprint("scope", i%2), fmt.Sprint("missing", i), role, domain, i != 1, i == 1)
		if i != 1 {
			groupExec(t, db, "INSERT INTO role_bindings(id,identity_ref_id,role,domain_id,operator_owned,created_at,updated_at) VALUES ($1,$2,$3,$4,$5,now(),now())", fmt.Sprintf("00000000-0000-4000-8000-%012d", 911+i), testIdentity, role, domain, i == 0)
		}
		b := 911 + i
		if i == 1 {
			b = 911
		}
		groupExec(t, db, "INSERT INTO role_binding_group_sources(binding_id,mapping_id) VALUES ($1,$2)", fmt.Sprintf("00000000-0000-4000-8000-%012d", b), fmt.Sprintf("00000000-0000-4000-8000-%012d", 901+i))
	}
	groupExec(t, db, "UPDATE scim_resources SET data=convert_to('malformed User','UTF8') WHERE resource_type='User'")
	return db
}
func TestGroupRecoveryAtomicAllRoles(t *testing.T) {
	db := recoveryDB(t)
	s := GroupRecoveryService{DB: db}
	ctx := context.Background()
	before := groupSnapshot(t, db)
	p, e := s.Preview(ctx)
	if e != nil || p.RemovedSources != 4 || p.ChangedMappings != 4 {
		t.Fatal(p, e)
	}
	if before != groupSnapshot(t, db) {
		t.Fatal("preview wrote")
	}
	v, e := s.Apply(ctx, p.PlanID)
	if e != nil || !v.Changed {
		t.Fatal(v, e)
	}
	groupCounts(t, db, 4, 1, 0, 10)
	var rev int
	var op bool
	if e = db.QueryRow("SELECT authority_revision,operator_owned FROM role_bindings WHERE id='00000000-0000-4000-8000-000000000911'").Scan(&rev, &op); e != nil || rev != 3 || !op {
		t.Fatal(rev, op, e)
	}
	p, e = s.Preview(ctx)
	if e != nil || p.ChangedMappings != 0 {
		t.Fatal(p, e)
	}
	before = groupSnapshot(t, db)
	v, e = s.Apply(ctx, p.PlanID)
	if e != nil || v.Changed || before != groupSnapshot(t, db) {
		t.Fatal("noop", v, e)
	}
	if _, e = s.Apply(ctx, strings.Repeat("0", 64)); e == nil {
		t.Fatal("bad confirmation")
	}
	groupExec(t, db, "INSERT INTO identity_group_role_mappings(id,issuer,scope,group_id,role,created_at,updated_at) SELECT ('00000000-0000-4000-8000-'||lpad((1100+i)::text,12,'0'))::uuid,'https://auth.example.test/application/o/gotth-mail/','population','missing-'||i,'global_admin',now(),now() FROM generate_series(1,32)i; INSERT INTO role_binding_group_sources(binding_id,mapping_id) SELECT '00000000-0000-4000-8000-000000000911',id FROM identity_group_role_mappings WHERE scope='population'")
	p, e = s.Preview(ctx)
	if e != nil || p.ChangedMappings != 32 || p.RemovedSources != 32 {
		t.Fatal(p, e)
	}
	start := time.Now()
	v, e = s.Apply(ctx, p.PlanID)
	if e != nil || !v.Changed {
		t.Fatal(v, e)
	}
	t.Logf("bounded native withdrawal M36 B1 E32 elapsed=%s; single sample not SLO", time.Since(start))
	groupCounts(t, db, 36, 1, 0, 75)

}
