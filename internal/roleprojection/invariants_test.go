package roleprojection_test

import (
	"context"
	"database/sql"
	"errors"
	"forgejo/gotthboard/gotth-mail/internal/authn"
	"forgejo/gotthboard/gotth-mail/internal/rolebinding"
	"github.com/lib/pq"
	"strings"
	"testing"
	"time"
)

const otherDomain = "00000000-0000-4000-8000-000000000006"

func TestProjectionRejectsMismatchedSourcesAndPreviewDenies(t *testing.T) {
	db := fixture(t)
	p := projector(issuer)
	syncIdentity(t, db, p)
	execSQL(t, db, "INSERT INTO domains(id,name,enabled,created_at,updated_at) VALUES ($1,'other.test',true,now(),now())", otherDomain)
	for _, kind := range []string{"domain", "role"} {
		t.Run(kind, func(t *testing.T) {
			execSQL(t, db, "UPDATE identity_group_role_mappings SET role='domain_manager',domain_id=$1", domain)
			if kind == "domain" {
				execSQL(t, db, "UPDATE identity_group_role_mappings SET domain_id=$1", otherDomain)
			} else {
				execSQL(t, db, "UPDATE identity_group_role_mappings SET role='scoped_domain_access'")
			}
			before := snapshot(t, db)
			for _, remove := range []bool{false, true} {
				e := transact(db, func(tx *sql.Tx) error {
					if remove {
						return p.RemoveMappingSources(ctx, tx, mapping1)
					}
					return p.SyncIdentity(ctx, tx, ident)
				})
				if e == nil {
					t.Fatal("mismatched edge accepted")
				}
				if snapshot(t, db) != before {
					t.Fatal("mismatch rejection mutated state")
				}
			}
			op := rolebinding.Service{DB: db, CurrentIssuer: issuer}
			request := rolebinding.Request{Operation: "revoke", Issuer: issuer, Subject: "subject", Mailbox: "member@example.test", Role: "domain_manager", Domain: "example.test"}
			plan, e := op.Preview(ctx, request)
			if e != nil {
				t.Fatal(e)
			}
			bound, ok := (authn.SQLStore{DB: db, CurrentIssuer: issuer}).BoundSession(ctx, "session", time.Now())
			if !ok || len(bound.Roles) != 0 || plan.EffectiveAfter {
				t.Fatalf("source invariant preview/read drift: plan=%+v roles=%+v ok=%v", plan, bound.Roles, ok)
			}
			execSQL(t, db, "UPDATE identity_group_role_mappings SET role='domain_manager',domain_id=$1", domain)
		})
	}
}
func TestProjectionSourceSwapPreservesBindingAndIndependentDomains(t *testing.T) {
	db := fixture(t)
	p := projector(issuer)
	execSQL(t, db, "UPDATE identity_group_role_mappings SET enabled=false WHERE id=$1", mapping2)
	syncIdentity(t, db, p)
	id := bindingID(t, db)
	e := transact(db, func(tx *sql.Tx) error {
		execSQL(t, tx, "UPDATE identity_group_role_mappings SET enabled=(id=$1)", mapping2)
		return p.SyncIdentity(ctx, tx, ident)
	})
	if e != nil {
		t.Fatal(e)
	}
	counts(t, db, 1, 1, 3)
	if bindingID(t, db) != id {
		t.Fatal("simultaneous origin swap replaced UUID")
	}
	execSQL(t, db, "INSERT INTO domains(id,name,enabled,created_at,updated_at) VALUES ($1,'other.test',false,now(),now())", otherDomain)
	execSQL(t, db, "UPDATE identity_group_role_mappings SET enabled=true,domain_id=$1 WHERE id=$2", otherDomain, mapping1)
	syncIdentity(t, db, p)
	counts(t, db, 2, 2, 4)
	bound, ok := (authn.SQLStore{DB: db, CurrentIssuer: issuer}).BoundSession(ctx, "session", time.Now())
	if !ok || len(bound.Roles) != 1 || bound.Roles[0].Domain != "example.test" {
		t.Fatalf("disabled independent target %#v %v", bound, ok)
	}
	before := snapshot(t, db)
	syncIdentity(t, db, p)
	if snapshot(t, db) != before {
		t.Fatal("disabled target removed structural origin")
	}
	execSQL(t, db, "UPDATE domains SET enabled=true WHERE id=$1", otherDomain)
	bound, ok = (authn.SQLStore{DB: db, CurrentIssuer: issuer}).BoundSession(ctx, "session", time.Now())
	if !ok || len(bound.Roles) != 2 {
		t.Fatal("local reenable lost origin")
	}
}
func TestProjectionDuplicateSubjectCannotSubstituteMailboxOwnership(t *testing.T) {
	db := fixture(t)
	execSQL(t, db, `INSERT INTO scim_resources(scope,resource_type,id,external_id,version,created_unix_nano,last_modified_unix_nano,data) VALUES ('scope','User','foreign-user','subject','v1',1,1,convert_to('{"active":true}','UTF8'))`)
	execSQL(t, db, "DELETE FROM scim_group_members; INSERT INTO scim_group_members(scope,group_id,user_id) VALUES ('scope','g1','foreign-user'),('scope','g2','foreign-user')")
	syncIdentity(t, db, projector(issuer))
	counts(t, db, 0, 0, 0)
	if e := transact(db, func(tx *sql.Tx) error { return projector(issuer).SyncGroup(ctx, tx, "scope", "g1") }); e != nil {
		t.Fatal(e)
	}
	counts(t, db, 0, 0, 0)
	execSQL(t, db, "UPDATE mailboxes SET scim_resource_id='foreign-user'")
	syncIdentity(t, db, projector(issuer))
	counts(t, db, 1, 2, 2) // exact owner link, not subject lookup, now makes it admissible.
	execSQL(t, db, "UPDATE mailboxes SET scim_resource_id='u'")
	syncIdentity(t, db, projector(""))
	counts(t, db, 0, 0, 4)
}
func TestProjectionRetractionAuditFailureRollsBackAndNoopRemoval(t *testing.T) {
	db := fixture(t)
	p := projector(issuer)
	syncIdentity(t, db, p)
	before := snapshot(t, db)
	execSQL(t, db, "CREATE FUNCTION fail_retraction() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN IF NEW.action='identity.group_role_source.remove' THEN RAISE EXCEPTION 'retraction audit failed'; END IF; RETURN NEW; END$$")
	execSQL(t, db, "CREATE TRIGGER fail_retraction BEFORE INSERT ON audit_events FOR EACH ROW EXECUTE FUNCTION fail_retraction()")
	for _, remove := range []bool{false, true} {
		e := transact(db, func(tx *sql.Tx) error {
			execSQL(t, tx, "UPDATE identity_group_role_mappings SET enabled=false,revision=revision+1")
			if remove {
				return projector("").RemoveMappingSources(ctx, tx, mapping1)
			}
			execSQL(t, tx, "DELETE FROM scim_resources WHERE resource_type='Group'")
			return projector("").SyncGroup(ctx, tx, "scope", "g1")
		})
		if e == nil {
			t.Fatal("retraction audit accepted")
		}
		if snapshot(t, db) != before {
			t.Fatal("retraction leaked state")
		}
	}
	execSQL(t, db, "DROP TRIGGER fail_retraction ON audit_events")
	if e := transact(db, func(tx *sql.Tx) error {
		execSQL(t, tx, "UPDATE identity_group_role_mappings SET enabled=false WHERE id=$1", mapping1)
		return p.RemoveMappingSources(ctx, tx, mapping1)
	}); e != nil {
		t.Fatal(e)
	}
	before = snapshot(t, db)
	if e := transact(db, func(tx *sql.Tx) error { return p.RemoveMappingSources(ctx, tx, mapping1) }); e != nil {
		t.Fatal(e)
	}
	if snapshot(t, db) != before {
		t.Fatal("repeat removal wrote state")
	}
}
func TestProjectionRejectsWrongTransactionAndMalformedUser(t *testing.T) {
	db := fixture(t)
	p := projector(issuer)
	before := snapshot(t, db)
	tx, e := db.BeginTx(ctx, nil)
	if e != nil {
		t.Fatal(e)
	}
	if e = p.SyncIdentity(ctx, tx, ident); e == nil {
		t.Fatal("READ COMMITTED caller accepted")
	}
	tx.Rollback()
	if e = p.SyncIdentity(ctx, nil, ident); e == nil {
		t.Fatal("nil tx accepted")
	}
	if e = transact(db, func(tx *sql.Tx) error { bad := p; bad.Actor.ID = ""; return bad.SyncIdentity(ctx, tx, ident) }); e == nil {
		t.Fatal("missing attribution accepted")
	}
	if e = transact(db, func(tx *sql.Tx) error {
		execSQL(t, tx, "UPDATE scim_resources SET data=$1 WHERE id='u'", []byte("not JSON"))
		return p.SyncIdentity(ctx, tx, ident)
	}); e == nil {
		t.Fatal("malformed canonical User accepted")
	}
	if snapshot(t, db) != before {
		t.Fatal("validation failure changed rows")
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if e = transact(db, func(tx *sql.Tx) error { return p.SyncIdentity(cancelled, tx, ident) }); e == nil {
		t.Fatal("cancelled projection accepted")
	}
}
func TestProjectionAbsentRowRaceNoReplay(t *testing.T) {
	db := fixture(t)
	runCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	a, e := db.BeginTx(runCtx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if e != nil {
		t.Fatal(e)
	}
	defer a.Rollback()
	b, e := db.BeginTx(runCtx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if e != nil {
		t.Fatal(e)
	}
	defer b.Rollback()
	for _, tx := range []*sql.Tx{a, b} {
		var n int
		if e = tx.QueryRowContext(runCtx, "SELECT count(*) FROM role_bindings").Scan(&n); e != nil || n != 0 {
			t.Fatal("absent snapshot", n, e)
		}
	}
	result := make(chan error, 2)
	for _, tx := range []*sql.Tx{a, b} {
		go func(tx *sql.Tx) {
			err := projector(issuer).SyncIdentity(runCtx, tx, ident)
			if err == nil {
				err = tx.Commit()
			} else {
				tx.Rollback()
			}
			result <- err
		}(tx)
	}
	success := 0
	for range 2 {
		err := <-result
		if err == nil {
			success++
			continue
		}
		var pg *pq.Error
		if !errors.As(err, &pg) || (pg.Code != "40001" && pg.Code != "23505" && pg.Code != "40P01") {
			t.Fatalf("unexpected race error %v", err)
		}
	}
	if success < 1 || success > 2 {
		t.Fatal("no successful transaction", success)
	}
	counts(t, db, 1, 2, 2)
	var auditJSON string
	if e = db.QueryRow("SELECT string_agg(after_redacted_json,'') FROM audit_events").Scan(&auditJSON); e != nil {
		t.Fatal(e)
	}
	for _, secret := range []string{issuer, "subject", "member@example.test", "members", "active"} {
		if strings.Contains(auditJSON, secret) {
			t.Fatalf("audit leaked %s: %s", secret, auditJSON)
		}
	}
}
