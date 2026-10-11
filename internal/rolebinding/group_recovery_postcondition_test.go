package rolebinding

import (
	"context"
	"testing"
)

func TestGroupRecoveryPostconditionAndStatementFaults(t *testing.T) {
	db := recoveryDB(t)
	s := GroupRecoveryService{DB: db}
	ctx := context.Background()
	for _, tc := range []struct{ table, body string }{{"identity_group_role_mappings", "RETURN NULL;"}, {"identity_group_role_mappings", "NEW.issuer:='https://tampered.example/application/o/gotth-mail/';RETURN NEW;"}, {"role_bindings", "IF NEW.id='00000000-0000-4000-8000-000000000911' THEN NEW.operator_owned:=false;END IF;RETURN NEW;"}} {
		groupExec(t, db, "CREATE OR REPLACE FUNCTION recovery_corrupt_write() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN "+tc.body+" END$$; CREATE TRIGGER recovery_corrupt BEFORE UPDATE ON "+tc.table+" FOR EACH ROW EXECUTE FUNCTION recovery_corrupt_write()")
		p, e := s.Preview(ctx)
		if e != nil {
			t.Fatal(e)
		}
		before := groupSnapshot(t, db)
		if _, e = s.Apply(ctx, p.PlanID); e == nil || before != groupSnapshot(t, db) {
			t.Fatal("postcondition/affected-row failure", tc, e)
		}
		groupExec(t, db, "DROP TRIGGER recovery_corrupt ON "+tc.table)
	}
	for _, table := range []string{"identity_group_role_mappings", "role_bindings"} {
		column := "revision"
		if table == "role_bindings" {
			column = "authority_revision"
		}
		groupExec(t, db, "UPDATE "+table+" SET "+column+"=9223372036854775807")
		p, e := s.Preview(ctx)
		if e != nil {
			t.Fatal(e)
		}
		before := groupSnapshot(t, db)
		if _, e = s.Apply(ctx, p.PlanID); e == nil || before != groupSnapshot(t, db) {
			t.Fatal("revision overflow", table, e)
		}
		groupExec(t, db, "UPDATE "+table+" SET "+column+"=1")
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, e := s.Preview(canceled); e == nil {
		t.Fatal("preview ignored canceled context")
	}
	if _, e := s.Apply(canceled, "x"); e == nil {
		t.Fatal("apply ignored canceled context")
	}
}
