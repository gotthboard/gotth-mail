package rolebinding

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"forgejo/gotthboard/gotth-mail/internal/store"
	"github.com/lib/pq"
	"strings"
	"sync"
	"testing"
	"time"
)

func recoveryConnect(t *testing.T, admin *sql.DB, role string) *sql.DB {
	t.Helper()
	var port string
	if e := admin.QueryRow("SHOW port").Scan(&port); e != nil {
		t.Fatal(e)
	}
	db, e := sql.Open("postgres", fmt.Sprintf("postgres://%s@127.0.0.1:%s/gotth_mail?sslmode=disable", role, port))
	if e != nil {
		t.Fatal(e)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { db.Close() })
	return db
}
func recoveryPrivileges(t *testing.T, admin *sql.DB) {
	t.Helper()
	groupExec(t, admin, "CREATE ROLE recovery_preview LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS; CREATE ROLE recovery_apply LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS; REVOKE ALL ON DATABASE gotth_mail FROM PUBLIC; GRANT CONNECT ON DATABASE gotth_mail TO recovery_preview,recovery_apply; REVOKE CREATE ON SCHEMA public FROM PUBLIC; GRANT USAGE ON SCHEMA public TO recovery_preview,recovery_apply; GRANT SELECT ON identity_group_role_mappings,role_bindings,role_binding_group_sources,identity_refs,domains,schema_migrations TO recovery_preview,recovery_apply; GRANT UPDATE ON identity_group_role_mappings,role_bindings TO recovery_apply; GRANT DELETE ON role_bindings,role_binding_group_sources TO recovery_apply; GRANT INSERT ON audit_events TO recovery_apply")
	var version int
	admin.QueryRow("SHOW server_version_num").Scan(&version)
	priv := "UPDATE"
	if version >= 170000 {
		priv = "MAINTAIN"
	}
	groupExec(t, admin, "GRANT "+priv+" ON schema_migrations TO recovery_apply")
}
func recoveryLedgerSnapshot(t *testing.T, db *sql.DB) string {
	t.Helper()
	var x string
	if e := db.QueryRow("SELECT jsonb_agg(to_jsonb(l) ORDER BY version)::text FROM schema_migrations l").Scan(&x); e != nil {
		t.Fatal(e)
	}
	return x
}
func TestGroupRecoveryExactACLAndNoop(t *testing.T) {
	admin := recoveryDB(t)
	recoveryPrivileges(t, admin)
	preview := recoveryConnect(t, admin, "recovery_preview")
	apply := recoveryConnect(t, admin, "recovery_apply")
	ctx := context.Background()
	ps := GroupRecoveryService{DB: preview}
	s := GroupRecoveryService{DB: apply}
	before := groupSnapshot(t, admin)
	ledger := recoveryLedgerSnapshot(t, admin)
	p, e := ps.Preview(ctx)
	if e != nil {
		t.Fatal(e)
	}
	q, e := s.Preview(ctx)
	if e != nil || q.PlanID == p.PlanID {
		t.Fatal("database-user digest", p, q, e)
	}
	for _, db := range []*sql.DB{preview, apply} {
		for _, q := range []string{"CREATE TABLE public.no_permission(x int)", "DELETE FROM public.audit_events WHERE false", "DELETE FROM public.schema_migrations WHERE false", "SET ROLE gotth_mail", "SET ROLE pg_database_owner", "CREATE SCHEMA no_permission", "UPDATE public.role_binding_group_sources SET binding_id=binding_id WHERE false"} {
			if _, e := db.Exec(q); e == nil {
				t.Fatal("excess privilege", q)
			}
		}
		var owns bool
		if e := db.QueryRow("SELECT EXISTS(SELECT 1 FROM pg_catalog.pg_class c JOIN pg_catalog.pg_roles r ON r.oid=c.relowner WHERE r.rolname=CURRENT_USER AND c.relnamespace='public'::pg_catalog.regnamespace)").Scan(&owns); e != nil || owns {
			t.Fatal("role owns public relation", owns, e)
		}
		var su, br, member bool
		if e := db.QueryRow("SELECT rolsuper,rolbypassrls,EXISTS(SELECT 1 FROM pg_catalog.pg_auth_members WHERE member=r.oid) FROM pg_catalog.pg_roles r WHERE rolname=CURRENT_USER").Scan(&su, &br, &member); e != nil || su || br || member {
			t.Fatal("unexpected role authority", e)
		}
	}
	if _, e = ps.Apply(ctx, p.PlanID); e == nil {
		t.Fatal("SELECT-only apply acquired locks")
	}
	if _, e = s.Apply(ctx, p.PlanID); e == nil {
		t.Fatal("cross-principal plan accepted")
	}
	if before != groupSnapshot(t, admin) {
		t.Fatal("denials wrote")
	}
	var version int
	admin.QueryRow("SHOW server_version_num").Scan(&version)
	_, uerr := apply.Exec("UPDATE public.schema_migrations SET dirty=dirty WHERE false")
	if (version >= 170000) != (uerr != nil) {
		t.Fatal("ledger capability", version, uerr)
	}
	groupExec(t, admin, "CREATE FUNCTION public.recovery_no_dml() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'recovery ledger DML denied'; END $$; CREATE TRIGGER recovery_ledger_no_dml BEFORE INSERT OR UPDATE OR DELETE ON schema_migrations FOR EACH STATEMENT EXECUTE FUNCTION public.recovery_no_dml()")
	// Existing complete-schema startup requires no schema ownership or DDL.
	if e = store.MigrateSQL(ctx, apply); e != nil {
		t.Fatal("initialized migration permission", e)
	}
	if e = store.MigrateSQL(ctx, preview); e == nil {
		t.Fatal("SELECT-only startup lock accepted")
	}
	start := time.Now()
	v, e := s.Apply(ctx, q.PlanID)
	if e != nil || !v.Changed {
		t.Fatal(v, e)
	}
	t.Logf("native recovery M4 B3 E4 elapsed=%s (single operation, not SLO)", time.Since(start))
	if ledger != recoveryLedgerSnapshot(t, admin) {
		t.Fatal("ledger wrote")
	}
	groupCounts(t, admin, 4, 1, 0, 10)
	groupExec(t, admin, "CREATE TRIGGER no_map_dml BEFORE INSERT OR UPDATE OR DELETE ON identity_group_role_mappings FOR EACH STATEMENT EXECUTE FUNCTION public.recovery_no_dml(); CREATE TRIGGER no_binding_dml BEFORE INSERT OR UPDATE OR DELETE ON role_bindings FOR EACH STATEMENT EXECUTE FUNCTION public.recovery_no_dml(); CREATE TRIGGER no_source_dml BEFORE INSERT OR UPDATE OR DELETE ON role_binding_group_sources FOR EACH STATEMENT EXECUTE FUNCTION public.recovery_no_dml(); CREATE TRIGGER no_audit_dml BEFORE INSERT OR UPDATE OR DELETE ON audit_events FOR EACH STATEMENT EXECUTE FUNCTION public.recovery_no_dml()")
	q, e = s.Preview(ctx)
	if e != nil {
		t.Fatal(e)
	}
	before = groupSnapshot(t, admin)
	v, e = s.Apply(ctx, q.PlanID)
	if e != nil || v.Changed || before != groupSnapshot(t, admin) {
		t.Fatal("no-op DML", v, e)
	}
	b, _ := json.Marshal(q)
	for _, secret := range []string{testIssuer, testSubject, "scope0", "missing0"} {
		if strings.Contains(string(b), secret) {
			t.Fatal("plan disclosure", secret)
		}
	}
}
func TestGroupRecoveryNamespaceRLSAndLocks(t *testing.T) {
	admin := recoveryDB(t)
	recoveryPrivileges(t, admin)
	db := recoveryConnect(t, admin, "recovery_apply")
	s := GroupRecoveryService{DB: db}
	ctx := context.Background()
	groupExec(t, admin, "CREATE SCHEMA hostile; CREATE FUNCTION public.current_database() RETURNS name LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'public function used'; END$$; GRANT TEMPORARY ON DATABASE gotth_mail TO recovery_apply")
	groupExec(t, db, "CREATE TEMP TABLE schema_migrations(x int); CREATE TEMP TABLE identity_group_role_mappings(x int); CREATE TEMP TABLE role_bindings(x int); CREATE TEMP TABLE role_binding_group_sources(x int); SET search_path=pg_temp,hostile,public,pg_catalog")
	groupExec(t, admin, "REVOKE TEMPORARY ON DATABASE gotth_mail FROM recovery_apply")
	p, e := s.Preview(ctx)
	if e != nil {
		t.Fatal("namespace", e)
	}
	before := groupSnapshot(t, admin)
	for _, table := range []string{"identity_group_role_mappings", "role_bindings", "role_binding_group_sources", "schema_migrations"} {
		groupExec(t, admin, "ALTER TABLE public."+table+" ENABLE ROW LEVEL SECURITY; CREATE POLICY hide_all ON public."+table+" USING(false)")
		if _, e = s.Preview(ctx); e == nil {
			t.Fatal("RLS preview hidden all", table)
		}
		if _, e = s.Apply(ctx, p.PlanID); e == nil {
			t.Fatal("RLS apply hidden all", table)
		}
		groupExec(t, admin, "DROP POLICY hide_all ON public."+table+"; ALTER TABLE public."+table+" DISABLE ROW LEVEL SECURITY")
	}
	if before != groupSnapshot(t, admin) {
		t.Fatal("RLS failure wrote")
	}
	lock, e := admin.Begin()
	if e != nil {
		t.Fatal(e)
	}
	if _, e = lock.Exec("LOCK TABLE public.role_binding_group_sources IN ACCESS EXCLUSIVE MODE"); e != nil {
		t.Fatal(e)
	}
	start := time.Now()
	_, e = s.Apply(ctx, p.PlanID)
	var pe *pq.Error
	if e == nil || !errors.As(e, &pe) || pe.Code != "55P03" || time.Since(start) > time.Second {
		t.Fatal("NOWAIT", e, time.Since(start))
	}
	lock.Rollback()
	// A complete real operation must bypass all hostile public/temp objects.
	v, e := s.Apply(ctx, p.PlanID)
	if e != nil || !v.Changed {
		t.Fatal(v, e)
	}
}
func TestGroupRecoveryServerStatementOrder(t *testing.T) {
	admin := recoveryDB(t)
	var port string
	admin.QueryRow("SHOW port").Scan(&port)
	connector, e := pq.NewConnector("postgres://gotth_mail@127.0.0.1:" + port + "/gotth_mail?sslmode=disable")
	if e != nil {
		t.Fatal(e)
	}
	var mu sync.Mutex
	var statements []string
	overflow := false
	db := sql.OpenDB(pq.ConnectorWithNoticeHandler(connector, func(e *pq.Error) {
		if e.Severity == "LOG" {
			mu.Lock()
			defer mu.Unlock()
			if len(statements) < 100 {
				statements = append(statements, e.Message)
			} else {
				overflow = true
			}
		}
	}))
	defer db.Close()
	db.SetMaxOpenConns(1)
	groupExec(t, db, "SET client_min_messages=log; SET log_statement='all'")
	s := GroupRecoveryService{DB: db}
	p, e := s.Preview(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	mu.Lock()
	statements = nil
	mu.Unlock()
	if _, e = s.Apply(context.Background(), p.PlanID); e != nil {
		t.Fatal(e)
	}
	mu.Lock()
	defer mu.Unlock()
	locks := 0
	expected := []string{"LOCK TABLE public.schema_migrations IN SHARE MODE NOWAIT", "LOCK TABLE public.identity_group_role_mappings IN SHARE ROW EXCLUSIVE MODE NOWAIT", "LOCK TABLE public.role_bindings IN SHARE ROW EXCLUSIVE MODE NOWAIT", "LOCK TABLE public.role_binding_group_sources IN SHARE ROW EXCLUSIVE MODE NOWAIT"}
	firstSelect := -1
	for i, q := range statements {
		if strings.Contains(q, "LOCK TABLE public.") {
			if locks >= len(expected) || !strings.Contains(q, expected[locks]) {
				t.Fatal("wrong ordered lock", locks)
			}
			locks++
		}
		if strings.Contains(strings.ToUpper(q), "SELECT ") {
			firstSelect = i
			if locks != 4 {
				t.Fatal("SELECT before all locks", locks)
			}
			break
		}
	}
	if overflow || firstSelect < 0 || locks != 4 {
		t.Fatalf("server order not proven notices=%d select=%d locks=%d overflow=%v", len(statements), firstSelect, locks, overflow)
	}
	t.Logf("server statement order: notices=%d first SELECT after4locks; bounded memory only", len(statements))
}
