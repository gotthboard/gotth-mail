package roleprojection_test

import (
	"database/sql"
	"forgejo/gotthboard/gotth-mail/internal/rolebinding"
	"testing"
)

func TestProjectionNativeTupleWorkAndLegacyOperatorFirst(t *testing.T) {
	db := fixture(t)
	p := projector(issuer)
	tx, e := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if e != nil {
		t.Fatal(e)
	}
	defer tx.Rollback()
	if e = p.SyncIdentity(ctx, tx, ident); e != nil {
		t.Fatal(e)
	}
	readWork := func() map[string][3]int64 {
		t.Helper()
		result := map[string][3]int64{}
		for _, table := range []string{"role_bindings", "role_binding_group_sources", "audit_events"} {
			var v [3]int64
			if e := tx.QueryRow("SELECT n_tup_ins,n_tup_upd,n_tup_del FROM pg_stat_xact_user_tables WHERE relname=$1", table).Scan(&v[0], &v[1], &v[2]); e != nil {
				t.Fatal(e)
			}
			result[table] = v
		}
		return result
	}
	work := readWork()
	for table, want := range map[string][3]int64{"role_bindings": {1, 2, 0}, "role_binding_group_sources": {2, 0, 0}, "audit_events": {2, 0, 0}} {
		if work[table] != want {
			t.Fatalf("native tuple work %s=%v want=%v", table, work[table], want)
		}
	}
	if e = p.SyncIdentity(ctx, tx, ident); e != nil {
		t.Fatal(e)
	}
	for table, after := range readWork() {
		if after != work[table] {
			t.Fatal("no-op tuple writes", table, work[table], after)
		}
	}
	t.Logf("native logical tuple work oneidentity/twosources: %+v; repeated reconciliation adds zero tuple DML; not wire/WAL counters", work)
	if e = tx.Rollback(); e != nil {
		t.Fatal(e)
	}
	counts(t, db, 0, 0, 0)
	const legacy = "00000000-0000-4000-8000-000000000777"
	execSQL(t, db, "INSERT INTO role_bindings(id,identity_ref_id,role,domain_id,created_at,updated_at) VALUES ($1,$2,'domain_manager',$3,now(),now())", legacy, ident, domain)
	syncIdentity(t, db, p)
	counts(t, db, 1, 2, 2)
	var owned bool
	if e = db.QueryRow("SELECT operator_owned FROM role_bindings WHERE id=$1", legacy).Scan(&owned); e != nil || !owned || bindingID(t, db) != legacy {
		t.Fatal("legacy owner/UUID changed", owned, e)
	}
	for _, id := range []string{mapping1, mapping2} {
		if e = transact(db, func(tx *sql.Tx) error {
			execSQL(t, tx, "UPDATE identity_group_role_mappings SET enabled=false WHERE id=$1", id)
			return p.RemoveMappingSources(ctx, tx, id)
		}); e != nil {
			t.Fatal(e)
		}
	}
	counts(t, db, 1, 0, 4)
	op := rolebinding.Service{DB: db, CurrentIssuer: issuer}
	request := rolebinding.Request{Operation: "revoke", Issuer: issuer, Subject: "subject", Mailbox: "member@example.test", Role: "domain_manager", Domain: "example.test"}
	plan, e := op.Preview(ctx, request)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = op.Apply(ctx, request, plan.PlanID); e != nil {
		t.Fatal(e)
	}
	counts(t, db, 0, 0, 5)
}
func TestProjectionDMLFailureRollbackAndUnsupportedMapping(t *testing.T) {
	db := fixture(t)
	p := projector(issuer)
	before := snapshot(t, db)
	execSQL(t, db, "CREATE FUNCTION reject_projection_dml() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'forced source DML error'; END$$")
	for _, target := range []struct{ table, operation string }{{"role_bindings", "INSERT"}, {"role_bindings", "UPDATE"}, {"role_binding_group_sources", "INSERT"}} {
		t.Run(target.table+target.operation, func(t *testing.T) {
			e := transact(db, func(tx *sql.Tx) error {
				execSQL(t, tx, "CREATE TRIGGER dml_error BEFORE "+target.operation+" ON "+target.table+" FOR EACH ROW EXECUTE FUNCTION reject_projection_dml()")
				return p.SyncIdentity(ctx, tx, ident)
			})
			if e == nil {
				t.Fatal("forced DML admitted")
			}
			if snapshot(t, db) != before {
				t.Fatal("DML failure leaked rows")
			}
		})
	}
	e := transact(db, func(tx *sql.Tx) error {
		// IDP-GROUP-007 now admits valid global roles. Corrupt unknown roles instead.
		execSQL(t, tx, "ALTER TABLE identity_group_role_mappings DROP CONSTRAINT identity_group_role_mappings_role_check, DROP CONSTRAINT identity_group_role_mappings_check; UPDATE identity_group_role_mappings SET role='unknown',domain_id=NULL")
		return p.SyncIdentity(ctx, tx, ident)
	})
	if e == nil {
		t.Fatal("unknown Group role admitted")
	}
	if snapshot(t, db) != before {
		t.Fatal("unsupported mapping mutated rows")
	}
	if e = transact(db, func(tx *sql.Tx) error { return p.SyncIdentity(ctx, tx, "00000000-0000-4000-8000-000000000999") }); e != nil {
		t.Fatal(e)
	}
	if snapshot(t, db) != before {
		t.Fatal("missing identity fabricated")
	}
	syncIdentity(t, db, p)
	before = snapshot(t, db)
	e = transact(db, func(tx *sql.Tx) error {
		execSQL(t, tx, "DELETE FROM scim_group_members; CREATE TRIGGER dml_error BEFORE DELETE ON role_binding_group_sources FOR EACH ROW EXECUTE FUNCTION reject_projection_dml()")
		return p.SyncGroup(ctx, tx, "scope", "g1")
	})
	if e == nil {
		t.Fatal("failed source removal admitted")
	}
	if snapshot(t, db) != before {
		t.Fatal("source removal failure leaked caller rows")
	}
}
