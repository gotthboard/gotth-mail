package roleprojection_test

import (
	"context"
	"database/sql"
	"fmt"
	"forgejo/gotthboard/gotth-mail/internal/audit"
	"forgejo/gotthboard/gotth-mail/internal/authn"
	"forgejo/gotthboard/gotth-mail/internal/rolebinding"
	"forgejo/gotthboard/gotth-mail/internal/roleprojection"
	"forgejo/gotthboard/gotth-mail/internal/store"
	"forgejo/gotthboard/gotth-mail/internal/testpg"
	"strings"
	"testing"
	"time"
)

const issuer = "https://auth.example/application/o/gotth-mail/"
const ident = "00000000-0000-4000-8000-000000000001"
const mailbox = "00000000-0000-4000-8000-000000000002"
const domain = "00000000-0000-4000-8000-000000000003"
const mapping1 = "00000000-0000-4000-8000-000000000004"
const mapping2 = "00000000-0000-4000-8000-000000000005"

var ctx = context.Background()

func projector(authority string) roleprojection.Projector {
	return roleprojection.Projector{CurrentIssuer: authority, Actor: audit.ActorRef{Type: "test", ID: "projection"}, CorrelationID: "projection-test"}
}
func execSQL(t *testing.T, db interface {
	Exec(string, ...any) (sql.Result, error)
}, q string, args ...any) {
	t.Helper()
	if _, e := db.Exec(q, args...); e != nil {
		t.Fatal(e)
	}
}
func fixture(t *testing.T) *sql.DB {
	t.Helper()
	db := testpg.DB(t, store.MigrateSQL)
	execSQL(t, db, "INSERT INTO domains(id,name,enabled,created_at,updated_at) VALUES ($1,'example.test',true,now(),now())", domain)
	execSQL(t, db, "INSERT INTO scim_resources(scope,resource_type,id,external_id,version,created_unix_nano,last_modified_unix_nano,data) VALUES ('scope','User','u','subject','v1',1,1,$1)", []byte(`{"id":"u","externalId":"subject","userName":"member@example.test"}`))
	for _, g := range []string{"g1", "g2"} {
		execSQL(t, db, "INSERT INTO scim_resources(scope,resource_type,id,version,created_unix_nano,last_modified_unix_nano,data) VALUES ('scope','Group',$1,'v1',1,1,$2)", g, []byte(fmt.Sprintf(`{"id":%q,"members":[{"value":"u"}]}`, g)))
		execSQL(t, db, "INSERT INTO scim_group_members(scope,group_id,user_id) VALUES ('scope',$1,'u')", g)
	}
	execSQL(t, db, "INSERT INTO mailboxes(id,domain_id,local_part,display_name,enabled,scim_resource_id,created_at,updated_at) VALUES ($1,$2,'member','Member',true,'u',now(),now())", mailbox, domain)
	execSQL(t, db, "INSERT INTO identity_refs(id,provider,issuer,subject,mailbox_id,created_at,updated_at) VALUES ($1,'authentik',$2,'subject',$3,now(),now())", ident, issuer, mailbox)
	now := time.Now().UTC()
	execSQL(t, db, "INSERT INTO sessions(id,identity_ref_id,csrf_secret_hash,auth_method,created_at,expires_at,last_seen_at) VALUES ('session',$1,'hash','oidc',$2,$3,$2)", ident, now.Add(-time.Minute), now.Add(time.Hour))
	for i, m := range []string{mapping1, mapping2} {
		execSQL(t, db, "INSERT INTO identity_group_role_mappings(id,issuer,scope,group_id,role,domain_id,created_at,updated_at) VALUES ($1,$2,'scope',$3,'domain_manager',$4,now(),now())", m, issuer, fmt.Sprint("g", i+1), domain)
	}
	return db
}
func transact(db *sql.DB, fn func(*sql.Tx) error) error {
	tx, e := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if e != nil {
		return e
	}
	defer tx.Rollback()
	if e = fn(tx); e != nil {
		return e
	}
	return tx.Commit()
}
func syncIdentity(t *testing.T, db *sql.DB, p roleprojection.Projector) {
	t.Helper()
	if e := transact(db, func(tx *sql.Tx) error { return p.SyncIdentity(ctx, tx, ident) }); e != nil {
		t.Fatal(e)
	}
}
func counts(t *testing.T, db *sql.DB, bindings, sources, audits int) {
	t.Helper()
	for table, want := range map[string]int{"role_bindings": bindings, "role_binding_group_sources": sources, "audit_events": audits} {
		var n int
		if e := db.QueryRow("SELECT count(*) FROM " + table).Scan(&n); e != nil || n != want {
			t.Fatalf("%s count=%d want=%d err=%v", table, n, want, e)
		}
	}
}
func snapshot(t *testing.T, db *sql.DB) string {
	t.Helper()
	var out strings.Builder
	for _, table := range []string{"domains", "mailboxes", "identity_refs", "sessions", "scim_resources", "scim_group_members", "identity_group_role_mappings", "role_bindings", "role_binding_group_sources", "audit_events"} {
		var s string
		if e := db.QueryRow("SELECT COALESCE(jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text),'[]')::text FROM " + table + " t").Scan(&s); e != nil {
			t.Fatal(e)
		}
		out.WriteString(table + s)
	}
	return out.String()
}
func bindingID(t *testing.T, db *sql.DB) string {
	t.Helper()
	var id string
	if e := db.QueryRow("SELECT id::text FROM role_bindings").Scan(&id); e != nil {
		t.Fatal(e)
	}
	return id
}
func TestSyncIdentityIndependentOriginsAndNoop(t *testing.T) {
	db := fixture(t)
	p := projector(issuer)
	syncIdentity(t, db, p)
	counts(t, db, 1, 2, 2)
	id := bindingID(t, db)
	var owned bool
	var rev int
	if e := db.QueryRow("SELECT operator_owned,authority_revision FROM role_bindings").Scan(&owned, &rev); e != nil || owned || rev < 2 {
		t.Fatalf("ownership/revision %v %d %v", owned, rev, e)
	}
	before := snapshot(t, db)
	syncIdentity(t, db, p)
	if snapshot(t, db) != before {
		t.Fatal("no-op mutated rows")
	}
	execSQL(t, db, "CREATE FUNCTION reject_projection_write() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'unexpected no-op write'; END$$")
	for _, table := range []string{"role_bindings", "role_binding_group_sources", "audit_events"} {
		execSQL(t, db, "CREATE TRIGGER no_write BEFORE INSERT OR UPDATE OR DELETE ON "+table+" FOR EACH STATEMENT EXECUTE FUNCTION reject_projection_write()")
	}
	syncIdentity(t, db, p)
	for _, table := range []string{"role_bindings", "role_binding_group_sources", "audit_events"} {
		execSQL(t, db, "DROP TRIGGER no_write ON "+table)
	}
	op := rolebinding.Service{DB: db, CurrentIssuer: issuer}
	req := rolebinding.Request{Operation: "grant", Issuer: issuer, Subject: "subject", Mailbox: "member@example.test", Role: "domain_manager", Domain: "example.test"}
	plan, e := op.Preview(ctx, req)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = op.Apply(ctx, req, plan.PlanID); e != nil {
		t.Fatal(e)
	}
	execSQL(t, db, "DELETE FROM scim_group_members WHERE group_id='g1'")
	if e = transact(db, func(tx *sql.Tx) error { return p.SyncGroup(ctx, tx, "scope", "g1") }); e != nil {
		t.Fatal(e)
	}
	counts(t, db, 1, 1, 4)
	if bindingID(t, db) != id {
		t.Fatal("binding UUID changed")
	}
	execSQL(t, db, "UPDATE identity_group_role_mappings SET enabled=false WHERE id=$1", mapping2)
	if e = transact(db, func(tx *sql.Tx) error { return p.RemoveMappingSources(ctx, tx, mapping2) }); e != nil {
		t.Fatal(e)
	}
	counts(t, db, 1, 0, 5)
	if bindingID(t, db) != id {
		t.Fatal("operator binding deleted")
	}
	req.Operation = "revoke"
	plan, e = op.Preview(ctx, req)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = op.Apply(ctx, req, plan.PlanID); e != nil {
		t.Fatal(e)
	}
	counts(t, db, 0, 0, 6)
}
func TestSyncIdentityExactPredicateAndCanonicalActive(t *testing.T) {
	db := fixture(t)
	cases := []struct {
		name, q string
		args    []any
		wantErr bool
	}{
		{name: "provider", q: "UPDATE identity_refs SET provider='local'"},
		{name: "identity-issuer", q: "UPDATE identity_refs SET issuer='https://other.example/'"},
		{name: "mapping-issuer", q: "UPDATE identity_group_role_mappings SET issuer='https://other.example/'"},
		{name: "subject", q: "UPDATE identity_refs SET subject='foreign'"},
		{name: "scope", q: "UPDATE identity_group_role_mappings SET scope='foreign'"},
		{name: "mailbox-link", q: "UPDATE mailboxes SET scim_resource_id=NULL"},
		{name: "foreign-user", q: "UPDATE scim_resources SET external_id='foreign' WHERE id='u'"},
		{name: "membership", q: "DELETE FROM scim_group_members"},
		{name: "disabled-mapping", q: "UPDATE identity_group_role_mappings SET enabled=false"},
		{name: "deleted-mapping", q: "UPDATE identity_group_role_mappings SET enabled=false,group_deleted=true"},
		{name: "deleted-group", q: "DELETE FROM scim_resources WHERE resource_type='Group'"},
		{name: "inactive", q: "UPDATE scim_resources SET data=$1 WHERE id='u'", args: []any{[]byte(`{"active":false}`)}},
		{name: "null-active", q: "UPDATE scim_resources SET data=$1 WHERE id='u'", args: []any{[]byte(`{"active":null}`)}, wantErr: true},
		{name: "string-active", q: "UPDATE scim_resources SET data=$1 WHERE id='u'", args: []any{[]byte(`{"active":"true"}`)}, wantErr: true},
		{name: "duplicate-active", q: "UPDATE scim_resources SET data=$1 WHERE id='u'", args: []any{[]byte(`{"active":true,"ACTIVE":false}`)}, wantErr: true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			tx, e := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
			if e != nil {
				t.Fatal(e)
			}
			defer tx.Rollback()
			execSQL(t, tx, c.q, c.args...)
			e = projector(issuer).SyncIdentity(ctx, tx, ident)
			if (e != nil) != c.wantErr {
				t.Fatalf("error=%v wantErr=%v", e, c.wantErr)
			}
			if !c.wantErr {
				var n int
				if e = tx.QueryRow("SELECT count(*) FROM role_bindings").Scan(&n); e != nil || n != 0 {
					t.Fatalf("unauthorized bindings=%d err=%v", n, e)
				}
			}
		})
	}
	for _, authority := range []string{"", "https://other.example/"} {
		syncIdentity(t, db, projector(authority))
		counts(t, db, 0, 0, 0)
	}
	syncIdentity(t, db, projector(issuer))
	counts(t, db, 1, 2, 2) // absent active is canonically true.
}
func TestRetractionUnderIssuerLossAndLocalToggles(t *testing.T) {
	db := fixture(t)
	p := projector(issuer)
	syncIdentity(t, db, p)
	id := bindingID(t, db)
	execSQL(t, db, "UPDATE mailboxes SET enabled=false; UPDATE domains SET enabled=false")
	before := snapshot(t, db)
	syncIdentity(t, db, p)
	if snapshot(t, db) != before {
		t.Fatal("local toggles erased structural origins")
	}
	execSQL(t, db, "UPDATE mailboxes SET enabled=true; UPDATE domains SET enabled=true")
	for _, authority := range []string{"https://other.example/", ""} {
		before = snapshot(t, db)
		syncIdentity(t, db, projector(authority))
		if snapshot(t, db) != before {
			t.Fatal("mere issuer change mutated origins")
		}
	}
	execSQL(t, db, "DELETE FROM scim_group_members WHERE group_id='g1'")
	if e := transact(db, func(tx *sql.Tx) error { return projector("https://other.example/").SyncGroup(ctx, tx, "scope", "g1") }); e != nil {
		t.Fatal(e)
	}
	counts(t, db, 1, 1, 3)
	if bindingID(t, db) != id {
		t.Fatal("surviving source UUID changed")
	}
	execSQL(t, db, "UPDATE identity_group_role_mappings SET enabled=false WHERE id=$1", mapping2)
	syncIdentity(t, db, projector(""))
	counts(t, db, 0, 0, 4)
	syncIdentity(t, db, p)
	counts(t, db, 0, 0, 4)
}
func TestGroupBeforeVerifiedLoginCannotFabricateIdentity(t *testing.T) {
	db := fixture(t)
	execSQL(t, db, "DELETE FROM sessions; DELETE FROM identity_refs")
	before := snapshot(t, db)
	if e := transact(db, func(tx *sql.Tx) error { return projector(issuer).SyncGroup(ctx, tx, "scope", "g1") }); e != nil {
		t.Fatal(e)
	}
	if snapshot(t, db) != before {
		t.Fatal("prelogin fabricated authority")
	}
}
func TestProjectionAuditFailureRollsBackCallerTables(t *testing.T) {
	db := fixture(t)
	before := snapshot(t, db)
	execSQL(t, db, "CREATE FUNCTION reject_projection_audit() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN IF (SELECT count(*) FROM audit_events)>0 THEN RAISE EXCEPTION 'audit failure after first source'; END IF; RETURN NEW; END$$")
	execSQL(t, db, "CREATE TRIGGER reject_audit BEFORE INSERT ON audit_events FOR EACH ROW EXECUTE FUNCTION reject_projection_audit()")
	e := transact(db, func(tx *sql.Tx) error {
		execSQL(t, tx, "UPDATE scim_resources SET version='v2'; UPDATE mailboxes SET display_name='Changed'; UPDATE identity_group_role_mappings SET revision=revision+1")
		return projector(issuer).SyncIdentity(ctx, tx, ident)
	})
	if e == nil {
		t.Fatal("audit error accepted")
	}
	if snapshot(t, db) != before {
		t.Fatal("audit failure leaked caller/source/binding/identity/session/audit writes")
	}
}
func TestProjectionPreviewReadAgreement(t *testing.T) {
	db := fixture(t)
	syncIdentity(t, db, projector(issuer))
	op := rolebinding.Service{DB: db, CurrentIssuer: issuer}
	req := rolebinding.Request{Operation: "revoke", Issuer: issuer, Subject: "subject", Mailbox: "member@example.test", Role: "domain_manager", Domain: "example.test"}
	check := func(want bool) {
		t.Helper()
		plan, e := op.Preview(ctx, req)
		if e != nil {
			t.Fatal(e)
		}
		bound, ok := (authn.SQLStore{DB: db, CurrentIssuer: op.CurrentIssuer}).BoundSession(ctx, "session", time.Now())
		if !ok || plan.EffectiveAfter != want || (len(bound.Roles) == 1) != want {
			t.Fatalf("preview=%+v bound=%+v ok=%v want=%v", plan, bound, ok, want)
		}
	}
	check(true)
	op.CurrentIssuer = ""
	check(false)
	op.CurrentIssuer = issuer
	execSQL(t, db, "UPDATE identity_group_role_mappings SET enabled=false")
	syncIdentity(t, db, projector(issuer))
	check(false)
}
