package rolebinding

import (
	"context"
	"strings"
	"testing"
)

func TestGroupMappingRejectsSourceInvariantAndOrphan(t *testing.T) {
	db := groupDB(t)
	s := GroupService{DB: db, CurrentIssuer: testIssuer}
	r := groupRequest()
	groupApply(t, s, r)
	r.Operation = "disable"
	const other = "00000000-0000-4000-8000-000000000998"
	const bad = "00000000-0000-4000-8000-000000000997"
	groupExec(t, db, "INSERT INTO domains(id,name,enabled,created_at,updated_at) VALUES ($1,'other.test',true,now(),now())", other)
	for _, kind := range []string{"domain", "role", "orphan"} {
		t.Run(kind, func(t *testing.T) {
			role := RoleDomainManager
			var domain any = other
			owned := kind != "orphan"
			if kind == "role" {
				role = RoleGlobalAdmin
				domain = nil
			}
			groupExec(t, db, "INSERT INTO role_bindings(id,identity_ref_id,role,domain_id,operator_owned,created_at,updated_at) VALUES ($1,$2,$3,$4,$5,now(),now())", bad, testIdentity, role, domain, owned)
			if kind != "orphan" {
				groupExec(t, db, "INSERT INTO role_binding_group_sources(binding_id,mapping_id) SELECT $1,id FROM identity_group_role_mappings WHERE group_id='g1'", bad)
			}
			before := groupSnapshot(t, db)
			_, e := s.Preview(context.Background(), r)
			if e == nil || (!strings.Contains(e.Error(), "invariant") && !strings.Contains(e.Error(), "source-less")) {
				t.Fatalf("invalid source plan accepted: %v", e)
			}
			if groupSnapshot(t, db) != before {
				t.Fatal("rejection mutated provenance")
			}
			groupExec(t, db, "DELETE FROM role_bindings WHERE id=$1", bad)
		})
	}
	groupApply(t, s, r)
	groupCounts(t, db, 1, 0, 0, 4)
}
