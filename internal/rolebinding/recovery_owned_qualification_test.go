package rolebinding

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"forgejo/gotthboard/gotth-mail/internal/store"
	"github.com/lib/pq"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Explicit owned equipment only. Compiled children are not parent coverage.
func TestRecoveryOwnedQualification(t *testing.T) {
	root := os.Getenv("RECOVERY_B_ROOT")
	if root == "" {
		t.Skip("explicit owned Phase B equipment required")
	}
	pg := os.Getenv("RECOVERY_B_PGBIN")
	dir := filepath.Join(root, os.Getenv("RECOVERY_B_LANE"))
	if e := os.Mkdir(dir, 0700); e != nil {
		t.Fatal(e)
	}
	provider := bProvider(t, dir)
	testIssuer := provider.issuer
	put := func(name, body string) string {
		p := filepath.Join(dir, name)
		if e := os.WriteFile(p, []byte(body), 0600); e != nil {
			t.Fatal(e)
		}
		return p
	}
	passwords := map[string]string{}
	for _, r := range []string{"b_admin", "b_maintenance", "b_old", "b_current", "b_rollback"} {
		b := make([]byte, 24)
		if _, e := rand.Read(b); e != nil {
			t.Fatal(e)
		}
		passwords[r] = hex.EncodeToString(b)
	}
	pw := put("admin-password.private", passwords["b_admin"])
	port := bFreePort(t)
	socket, e := os.MkdirTemp("/home/linus/id26/s", "b-")
	if e != nil {
		t.Fatal(e)
	}
	data := filepath.Join(dir, "data")
	bRun(t, dir, "initdb", nil, filepath.Join(pg, "initdb"), "-D", data, "-U", "b_admin", "--auth-local=scram-sha-256", "--auth-host=scram-sha-256", "--pwfile="+pw, "--no-clean")
	hba, e := os.ReadFile(filepath.Join(data, "pg_hba.conf"))
	if e != nil {
		t.Fatal(e)
	}
	for _, line := range strings.Split(string(hba), "\n") {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") && !strings.HasSuffix(line, "scram-sha-256") {
			t.Fatal("unexpected HBA method")
		}
	}
	put("hba.sha256", fmt.Sprintf("%x\n", sha256.Sum256(hba)))
	pgcmd := bStart(t, dir, "postgres", nil, filepath.Join(pg, "postgres"), "-D", data, "-h", "127.0.0.1", "-p", port, "-k", socket, "-c", "shared_memory_type=mmap", "-c", "dynamic_shared_memory_type=mmap", "-c", "log_statement=none", "-c", "log_min_error_statement=panic")
	defer pgcmd.stop(t)
	dsn := func(role, db, pass string) string {
		return fmt.Sprintf("host=127.0.0.1 port=%s dbname=%s user=%s password=%s sslmode=disable connect_timeout=2 application_name=%s", port, db, role, pass, role)
	}
	connect := func(role, db string) *sql.DB {
		x, e := sql.Open("postgres", dsn(role, db, passwords[role]))
		if e != nil {
			t.Fatal(e)
		}
		x.SetMaxOpenConns(3)
		t.Cleanup(func() { x.Close() })
		return x
	}
	admin := connect("b_admin", "postgres")
	bUntil(t, 5*time.Second, func() bool { return admin.Ping() == nil }, "owned PG readiness")
	var actualDir, actualPort, ver string
	if e := admin.QueryRow("SELECT current_setting('data_directory'),current_setting('port'),current_setting('server_version_num')").Scan(&actualDir, &actualPort, &ver); e != nil || actualDir != data || actualPort != port || ver != os.Getenv("GOTTH_MAIL_TEST_PG_VERSION_NUM") {
		t.Fatal("owned PG identity", e)
	}
	t.Logf("owned PG pid=%d data=%s port=%s version=%s SCRAM", pgcmd.cmd.Process.Pid, data, port, ver)
	sqlx := func(db *sql.DB, q string, args ...any) {
		t.Helper()
		if _, e := db.Exec(q, args...); e != nil {
			t.Fatal("SQL", e)
		}
	}
	sqlx(admin, "CREATE DATABASE recovery_b OWNER b_admin")
	db := connect("b_admin", "recovery_b")
	if e := store.MigrateEmptySQL(context.Background(), db); e != nil {
		t.Fatal(e)
	}
	for _, role := range []string{"b_maintenance", "b_old", "b_current", "b_rollback"} {
		sqlx(admin, "CREATE ROLE "+role+" LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS PASSWORD "+pq.QuoteLiteral(passwords[role]))
	}
	sqlx(db, "REVOKE ALL ON DATABASE recovery_b FROM PUBLIC; REVOKE CREATE ON SCHEMA public FROM PUBLIC; GRANT CONNECT ON DATABASE recovery_b TO b_maintenance,b_old,b_current,b_rollback; GRANT USAGE ON SCHEMA public TO b_maintenance,b_old,b_current,b_rollback")
	bad := func(role, pass string) {
		x, e := sql.Open("postgres", dsn(role, "recovery_b", pass))
		if e != nil {
			t.Fatal(e)
		}
		defer x.Close()
		if e = x.Ping(); e == nil {
			t.Fatal("unexpected authentication", role)
		}
		t.Logf("authentication denied role=%s", role)
	}
	bad("b_old", "wrong")
	for _, role := range []string{"b_admin", "b_maintenance", "b_current", "b_rollback", "missing_role"} {
		bad(role, passwords["b_old"])
	}
	sqlx(db, "GRANT SELECT ON identity_refs,mailboxes,domains,role_bindings TO b_old; GRANT UPDATE ON identity_refs,mailboxes,domains TO b_old; GRANT DELETE ON role_bindings TO b_old; GRANT INSERT ON audit_events TO b_old")
	sqlx(db, "GRANT SELECT ON identity_group_role_mappings,role_bindings,role_binding_group_sources,identity_refs,domains,schema_migrations TO b_maintenance; GRANT UPDATE ON identity_group_role_mappings,role_bindings TO b_maintenance; GRANT DELETE ON role_bindings,role_binding_group_sources TO b_maintenance; GRANT INSERT ON audit_events TO b_maintenance")
	priv := "UPDATE"
	if strings.HasPrefix(ver, "17") {
		priv = "MAINTAIN"
	}
	sqlx(db, "GRANT "+priv+" ON schema_migrations TO b_maintenance,b_current,b_rollback")
	sqlx(db, "GRANT SELECT ON schema_migrations,domains,mailboxes,tokens,identity_refs,role_bindings,role_binding_group_sources,identity_group_role_mappings,sessions,scim_resources,scim_group_members TO b_current,b_rollback; GRANT UPDATE ON identity_refs,domains,mailboxes,role_bindings TO b_current,b_rollback; GRANT INSERT,DELETE ON role_bindings TO b_current,b_rollback; GRANT INSERT ON audit_events TO b_current,b_rollback")
	for _, role := range []string{"b_maintenance", "b_old", "b_current", "b_rollback"} {
		x := connect(role, "recovery_b")
		if e := x.Ping(); e != nil {
			t.Fatal("actual role authentication", e)
		}
		for _, q := range []string{"SET ROLE b_admin", "SET ROLE b_maintenance", "SET ROLE pg_database_owner", "CREATE TABLE public.forbidden(x int)", "DELETE FROM audit_events WHERE false", "DELETE FROM schema_migrations WHERE false"} {
			if role == "b_maintenance" && q == "SET ROLE b_maintenance" {
				continue
			}
			if _, e := x.Exec(q); e == nil {
				t.Fatal("excess privilege", role, q)
			}
		}
		var n int
		if e := db.QueryRow("SELECT count(*) FROM pg_roles r WHERE rolname=$1 AND (rolsuper OR rolcreaterole OR rolcreatedb OR rolbypassrls OR EXISTS(SELECT 1 FROM pg_auth_members WHERE member=r.oid) OR EXISTS(SELECT 1 FROM pg_class c WHERE c.relowner=r.oid))", role).Scan(&n); e != nil || n != 0 {
			t.Fatal("authority escape", role, e)
		}
		x.Close()
	}
	sqlx(db, "ALTER ROLE b_current NOLOGIN; ALTER ROLE b_rollback NOLOGIN")
	sqlx(db, "INSERT INTO domains(id,name,enabled,created_at,updated_at) VALUES ($1,'example.test',true,now(),now())", testDomain)
	sqlx(db, "INSERT INTO mailboxes(id,domain_id,local_part,enabled,created_at,updated_at) VALUES ('00000000-0000-4000-8000-000000000182',$1,'admin',true,now(),now())", testDomain)
	sqlx(db, "INSERT INTO identity_refs(id,provider,issuer,subject,mailbox_id,created_at,updated_at) VALUES ($1,'authentik',$2,$3,'00000000-0000-4000-8000-000000000182',now(),now())", testIdentity, testIssuer, testSubject)
	seedUTC := time.Now().UTC()
	sqlx(db, "INSERT INTO sessions(id,identity_ref_id,csrf_secret_hash,auth_method,created_at,expires_at,last_seen_at) VALUES ('existing-session',$1,'hash','oidc',$2,$3,$2)", testIdentity, seedUTC.Add(-time.Minute), seedUTC.Add(time.Hour))
	for i, role := range []string{RoleGlobalAdmin, RoleDomainManager, RoleScopedDomainAccess} {
		var domain any
		if i > 0 {
			domain = testDomain
		}
		mapping := fmt.Sprintf("00000000-0000-4000-8000-%012d", 901+i)
		binding := fmt.Sprintf("00000000-0000-4000-8000-%012d", 911+i)
		sqlx(db, "INSERT INTO identity_group_role_mappings(id,issuer,scope,group_id,role,domain_id,created_at,updated_at) VALUES ($1,$2,'scope','g',$3,$4,now(),now())", mapping, testIssuer, role, domain)
		sqlx(db, "INSERT INTO role_bindings(id,identity_ref_id,role,domain_id,operator_owned,created_at,updated_at) VALUES ($1,$2,$3,$4,$5,now(),now())", binding, testIdentity, role, domain, i == 0)
		sqlx(db, "INSERT INTO role_binding_group_sources(binding_id,mapping_id) VALUES ($1,$2)", binding, mapping)
	}
	resourceID := bSeedProtocol(t, db, testIssuer)
	configs := map[string]string{}
	for _, role := range []string{"b_old", "b_maintenance", "b_current", "b_rollback"} {
		configs[role] = put(role+".private.yaml", fmt.Sprintf("server:\n  public_url: https://mail.example.test\n  listen: ':8080'\n  environment: development\ndatabase:\n  dsn: %q\ntls:\n  mode: manual\n  cert_path: cert.pem\n  key_path: key.pem\nauthentik:\n  enabled: true\n  base_url: https://not-authority.example\nroles:\n  global_admin_group: admins\n  domain_manager_group: managers\n  scoped_domain_group_prefix: domain-\nrender:\n  staging_dir: %s\n  applied_dir: %s\n", dsn(role, "recovery_b", passwords[role]), filepath.Join(dir, "stage"), filepath.Join(dir, "applied")))
	}
	authority := put("authority.json", fmt.Sprintf("{\"GOTTH_MAIL_AUTHENTIK_ISSUER\":%q}", testIssuer))
	env := []string{"GOTTH_MAIL_IDENTITY_RUNTIME_CONFIG_FILE=" + authority}
	oldbin := filepath.Join(root, "legacy-bin/gotth-mailctl")
	currentbin := filepath.Join(filepath.Dir(root), "gotth-mail-identity-recovery-a-20261003/final-build/gotth-mailctl")
	args := []string{"identity", "role-binding", "preview", "--config", configs["b_old"], "--operation", "revoke", "--issuer", testIssuer, "--subject", testSubject, "--mailbox", testMailbox, "--role", RoleGlobalAdmin}
	out := bRun(t, dir, "legacy-preview", env, oldbin, args...)
	var plan Plan
	if e := json.Unmarshal(out, &plan); e != nil || plan.Operation != "revoke" || len(plan.PlanID) != 64 {
		t.Fatal("not a changing legacy control", e)
	}
	ledger := recoveryLedgerSnapshot(t, db)
	before := groupSnapshot(t, db)
	blocker, e := db.Begin()
	if e != nil {
		t.Fatal(e)
	}
	defer blocker.Rollback()
	if _, e := blocker.Exec("SELECT id FROM identity_refs WHERE id=$1 FOR UPDATE", testIdentity); e != nil {
		t.Fatal(e)
	}
	var blockerPID int
	if e := blocker.QueryRow("SELECT pg_backend_pid()").Scan(&blockerPID); e != nil {
		t.Fatal(e)
	}
	old := connect("b_old", "recovery_b")
	old.SetMaxOpenConns(1)
	var establishedPID int
	var establishedStart time.Time
	if e := old.QueryRow("SELECT pg_backend_pid(),backend_start FROM pg_stat_activity WHERE pid=pg_backend_pid()").Scan(&establishedPID, &establishedStart); e != nil {
		t.Fatal(e)
	}
	args[2] = "apply"
	args = append(args, "--confirm", plan.PlanID)
	blocked := bStart(t, dir, "legacy-apply", env, oldbin, args...)
	defer blocked.stop(t)
	var waitedPID int
	var waitedStart time.Time
	bUntil(t, 4*time.Second, func() bool {
		return db.QueryRow("SELECT pid,backend_start FROM pg_stat_activity WHERE datname='recovery_b' AND usename='b_old' AND application_name='b_old' AND wait_event_type='Lock' AND query LIKE '%FOR UPDATE OF ir, m, md%' AND $1=ANY(pg_blocking_pids(pid))", blockerPID).Scan(&waitedPID, &waitedStart) == nil
	}, "legacy identity row lock wait")
	var prepared int
	if e := db.QueryRow("SELECT count(*) FROM pg_prepared_xacts").Scan(&prepared); e != nil || prepared != 0 {
		t.Fatal("prepared transactions", e)
	}
	t.Logf("legacy OS_PID=%d waiting_backend=%d/%s separate_backend=%d/%s", blocked.cmd.Process.Pid, waitedPID, waitedStart.UTC().Format(time.RFC3339Nano), establishedPID, establishedStart.UTC().Format(time.RFC3339Nano))
	sqlx(db, "REVOKE CONNECT ON DATABASE recovery_b FROM PUBLIC,b_old; ALTER ROLE b_old NOLOGIN")
	bad("b_old", passwords["b_old"])
	var one int
	if e := old.QueryRow("SELECT 1").Scan(&one); e != nil || one != 1 {
		t.Fatal("NOLOGIN killed established session", e)
	}
	for _, x := range []struct {
		pid   int
		start time.Time
	}{{waitedPID, waitedStart}, {establishedPID, establishedStart}} {
		var killed bool
		if e := db.QueryRow("SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE pid=$1 AND backend_start=$2 AND datname='recovery_b' AND usename='b_old' AND application_name='b_old'", x.pid, x.start).Scan(&killed); e != nil || !killed {
			t.Fatal("owned termination mismatch", e)
		}
	}
	if blocked.wait(t, 4*time.Second) == 0 {
		t.Fatal("terminated old apply succeeded")
	}
	errlog, _ := os.ReadFile(filepath.Join(dir, "legacy-apply.stderr"))
	serverLog, logErr := os.ReadFile(filepath.Join(dir, "postgres.stderr"))
	if logErr != nil || !bytes.Contains(serverLog, []byte(fmt.Sprintf("[%d] FATAL:  terminating connection due to administrator command", waitedPID))) || !bytes.Contains(errlog, []byte("driver: bad connection")) {
		t.Fatal("nonzero exit lacks matched backend termination/driver cause")
	}
	if before != groupSnapshot(t, db) {
		t.Fatal("legacy mutation escaped")
	}
	blocker.Rollback()
	old.Close()
	t.Log("DISCRIMINATING_FENCE_PASS established session survived NOLOGIN; exact blocked backend terminated; state unchanged")
	ra := []string{"identity", "group-feature-disable", "preview", "--config", configs["b_maintenance"]}
	out = bRun(t, dir, "withdraw-preview", nil, currentbin, ra...)
	var rp RecoveryPlan
	if e := json.Unmarshal(out, &rp); e != nil || rp.ChangedMappings != 3 || rp.RemovedSources != 3 {
		t.Fatal("withdraw preview", e)
	}
	ra[2] = "apply"
	ra = append(ra, "--confirm", rp.PlanID)
	bRun(t, dir, "withdraw-apply", nil, currentbin, ra...)
	invariant := func() {
		t.Helper()
		var n int
		if e := db.QueryRow("SELECT (SELECT count(*) FROM identity_group_role_mappings WHERE enabled)+(SELECT count(*) FROM role_binding_group_sources)+(SELECT count(*) FROM role_bindings WHERE NOT operator_owned)").Scan(&n); e != nil || n != 0 {
			t.Fatal("withdrawal invariant", e)
		}
		if ledger != recoveryLedgerSnapshot(t, db) {
			t.Fatal("ledger changed")
		}
		var id string
		var rev int
		if e := db.QueryRow("SELECT id::text,authority_revision FROM role_bindings WHERE role='global_admin' AND operator_owned").Scan(&id, &rev); e != nil || id != "00000000-0000-4000-8000-000000000911" || rev != 2 {
			t.Fatal("operator changed", e)
		}
	}
	invariant()
	for _, kind := range []string{"current", "rollback"} {
		role := "b_" + kind
		binDir := filepath.Dir(currentbin)
		if kind == "rollback" {
			binDir = filepath.Join(root, "rollback-bin")
			sqlx(db, "REVOKE CONNECT ON DATABASE recovery_b FROM b_current; ALTER ROLE b_current NOLOGIN")
			bad("b_current", passwords["b_current"])
		}
		sqlx(db, "ALTER ROLE "+role+" LOGIN")
		dbfile := put(kind+"-dsn.private", dsn(role, "recovery_b", passwords[role]))
		addr := "127.0.0.1:" + bFreePort(t)
		front := bFrontend(t, addr)
		mapAddr := "127.0.0.1:" + bFreePort(t)
		serviceEnv := append([]string{"GOTTH_MAIL_DATABASE_URL_FILE=" + dbfile, "GOTTH_MAIL_LISTEN=" + addr, "GOTTH_MAIL_POSTFIX_DOMAIN_MAP_LISTEN=" + mapAddr}, provider.env(front.URL, authority)...)
		service := bStart(t, dir, kind+"-service", serviceEnv, filepath.Join(binDir, "gotth-mail"))
		client := http.Client{Timeout: time.Second}
		bUntil(t, 5*time.Second, func() bool {
			res, e := client.Get("http://" + addr + "/healthz")
			if e != nil {
				return false
			}
			defer res.Body.Close()
			return res.StatusCode == 200
		}, kind+" process health")
		t.Logf("ACTUAL_CORE_START kind=%s PID=%d fixture=off optionalworkers=off", kind, service.cmd.Process.Pid)
		provider.exercise(t, db, front.URL, kind, resourceID, front.Client())
		bDaemon(t, mapAddr)
		bad("b_old", passwords["b_old"])
		denied := bStart(t, dir, kind+"-old-entrypoint", env, oldbin, args...)
		if denied.wait(t, 4*time.Second) == 0 {
			t.Fatal("old entrypoint resumed")
		}
		ca := []string{"identity", "role-binding", "preview", "--config", configs[role], "--operation", "grant", "--issuer", testIssuer, "--subject", testSubject, "--mailbox", testMailbox, "--role", RoleGlobalAdmin}
		raw := bRun(t, dir, kind+"-operator-preview", env, filepath.Join(binDir, "gotth-mailctl"), ca...)
		var cp Plan
		if e := json.Unmarshal(raw, &cp); e != nil || cp.Operation != "unchanged" {
			t.Fatal("operator preservation", e)
		}
		ca[2] = "apply"
		ca = append(ca, "--confirm", cp.PlanID)
		bRun(t, dir, kind+"-operator-noop", env, filepath.Join(binDir, "gotth-mailctl"), ca...)
		for _, op := range []string{"grant", "revoke"} {
			a := []string{"identity", "role-binding", "preview", "--config", configs[role], "--operation", op, "--issuer", testIssuer, "--subject", "ordinary-subject", "--mailbox", "ordinary@example.test", "--role", RoleDomainManager, "--domain", "example.test"}
			raw := bRun(t, dir, kind+"-"+op+"-preview", env, filepath.Join(binDir, "gotth-mailctl"), a...)
			var q Plan
			if e := json.Unmarshal(raw, &q); e != nil || q.Operation != op {
				t.Fatal("changing operator plan", e)
			}
			a[2] = "apply"
			a = append(a, "--confirm", q.PlanID)
			raw = bRun(t, dir, kind+"-"+op+"-apply", env, filepath.Join(binDir, "gotth-mailctl"), a...)
			var result Result
			if e := json.Unmarshal(raw, &result); e != nil || !result.Changed {
				t.Fatal("actual operator change", e)
			}
		}
		oldPID := service.cmd.Process.Pid
		service.stop(t)
		invariant()
		if kind == "current" {
			service = bStart(t, dir, "current-restart", serviceEnv, filepath.Join(binDir, "gotth-mail"))
			if service.cmd.Process.Pid == oldPID {
				t.Fatal("restart reused PID")
			}
			bUntil(t, 5*time.Second, func() bool {
				res, e := client.Get("http://" + addr + "/readyz")
				if e != nil {
					return false
				}
				res.Body.Close()
				return res.StatusCode == 200
			}, "current actual restart")
			provider.exercise(t, db, front.URL, "current-restart", resourceID, front.Client())
			bad("b_old", passwords["b_old"])
			bDaemon(t, mapAddr)
			denied := bStart(t, dir, "current-restart-old-entrypoint", env, oldbin, args...)
			if denied.wait(t, 4*time.Second) == 0 {
				t.Fatal("old entrypoint after restart")
			}
			service.stop(t)
		}
		front.Close()
		bUntil(t, 3*time.Second, func() bool {
			var n int
			e := db.QueryRow("SELECT count(*) FROM pg_stat_activity WHERE datname='recovery_b' AND usename=$1", role).Scan(&n)
			return e == nil && n == 0
		}, "runtime sessions closed")
	}
	sqlx(db, "REVOKE CONNECT ON DATABASE recovery_b FROM b_rollback,b_maintenance; ALTER ROLE b_rollback NOLOGIN; ALTER ROLE b_maintenance NOLOGIN")
	var live int
	if e := db.QueryRow("SELECT count(*) FROM pg_stat_activity WHERE datname='recovery_b' AND usename<>'b_admin'").Scan(&live); e != nil || live != 0 {
		t.Fatal("no-write cut sessions", e)
	}
	backupState := groupSnapshot(t, db)
	dump := filepath.Join(dir, "backup.dump")
	pgEnv := []string{"PGHOST=127.0.0.1", "PGPORT=" + port, "PGUSER=b_admin", "PGPASSWORD=" + passwords["b_admin"]}
	bRun(t, dir, "dump", pgEnv, filepath.Join(pg, "pg_dump"), "--format=custom", "--no-owner", "--no-acl", "--file="+dump, "recovery_b")
	sqlx(db, "INSERT INTO domains(id,name,enabled,created_at,updated_at) VALUES ('00000000-0000-4000-8000-000000009999','later.test',true,now(),now())")
	sqlx(admin, "CREATE DATABASE recovery_b_restore OWNER b_admin TEMPLATE template0")
	restored := connect("b_admin", "recovery_b_restore")
	var relations int
	if e := restored.QueryRow("SELECT count(*) FROM pg_class WHERE relnamespace='public'::regnamespace").Scan(&relations); e != nil || relations != 0 {
		t.Fatal("restore target not empty", e)
	}
	bRun(t, dir, "restore", pgEnv, filepath.Join(pg, "pg_restore"), "--exit-on-error", "--no-owner", "--no-acl", "--dbname=recovery_b_restore", dump)
	if groupSnapshot(t, restored) != backupState || recoveryLedgerSnapshot(t, restored) != ledger {
		t.Fatal("restore logical mismatch")
	}
	var sentinel int
	if e := restored.QueryRow("SELECT count(*) FROM domains WHERE name='later.test'").Scan(&sentinel); e != nil || sentinel != 0 {
		t.Fatal("sentinel not lost", e)
	}
	t.Log("OWNED_DUMP_RESTORE_PASS no-owner/no-acl excludes SQL ACL restoration; business grants/history/ledger equal; later sentinel absent")
	invariant()
	t.Log("B_SCENARIO_PASS owned native protocol/fence/current restart/compatible-pair/restore; no external host credential isolation claim")
}

type bProcess struct {
	cmd      *exec.Cmd
	out, err *os.File
	done     chan error
	finished bool
	code     int
}

func bStart(t *testing.T, dir, name string, extra []string, bin string, args ...string) *bProcess {
	t.Helper()
	out, e := os.OpenFile(filepath.Join(dir, name+".stdout"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		t.Fatal(e)
	}
	errf, e := os.OpenFile(filepath.Join(dir, name+".stderr"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		t.Fatal(e)
	}
	cmd := exec.Command(bin, args...)
	cmd.Env = append([]string{"PATH=/usr/bin:/bin", "HOME=" + dir}, extra...)
	cmd.Stdout = out
	cmd.Stderr = errf
	if e := cmd.Start(); e != nil {
		t.Fatal(e)
	}
	p := &bProcess{cmd: cmd, out: out, err: errf, done: make(chan error, 1)}
	go func() { p.done <- cmd.Wait() }()
	t.Cleanup(func() {
		if !p.finished {
			p.stop(t)
		}
	})
	limits, limitErr := os.ReadFile(fmt.Sprintf("/proc/%d/limits", cmd.Process.Pid))
	if limitErr != nil {
		t.Fatal(limitErr)
	}
	if e := os.WriteFile(filepath.Join(dir, name+".limits"), limits, 0600); e != nil {
		t.Fatal(e)
	}
	f, e := os.Open(fmt.Sprintf("/proc/%d/exe", cmd.Process.Pid))
	if e != nil {
		t.Fatal(e)
	}
	h := sha256.New()
	_, e = io.Copy(h, f)
	f.Close()
	if e != nil {
		t.Fatal(e)
	}
	t.Logf("native %s pid=%d exe_sha256=%x argv=%q env=PATH,HOME plus %d private config values", name, cmd.Process.Pid, h.Sum(nil), cmd.Args, len(extra))
	return p
}
func (p *bProcess) wait(t *testing.T, d time.Duration) int {
	t.Helper()
	if p.finished {
		return p.code
	}
	select {
	case e := <-p.done:
		p.finished = true
		p.out.Close()
		p.err.Close()
		p.code = 0
		if e != nil {
			p.code = p.cmd.ProcessState.ExitCode()
		}
		t.Logf("native exit pid=%d code=%d state=%s", p.cmd.Process.Pid, p.code, p.cmd.ProcessState.String())
		return p.code
	case <-time.After(d):
		t.Fatal("owned process deadline")
		return -999
	}
}
func (p *bProcess) stop(t *testing.T) {
	t.Helper()
	if p.finished {
		return
	}
	select {
	case e := <-p.done:
		p.finished = true
		p.out.Close()
		p.err.Close()
		p.code = 0
		if e != nil {
			p.code = p.cmd.ProcessState.ExitCode()
		}
		t.Logf("already exited pid=%d code=%d", p.cmd.Process.Pid, p.code)
	default:
		_ = p.cmd.Process.Signal(os.Interrupt)
		select {
		case e := <-p.done:
			p.finished = true
			p.out.Close()
			p.err.Close()
			p.code = 0
			if e != nil {
				p.code = p.cmd.ProcessState.ExitCode()
			}
			t.Logf("owned stop pid=%d state=%s", p.cmd.Process.Pid, p.cmd.ProcessState)
		case <-time.After(20 * time.Second):
			_ = p.cmd.Process.Kill()
			p.wait(t, 2*time.Second)
			t.Error("forced containment, not graceful closure")
		}
	}
}
func bRun(t *testing.T, dir, name string, env []string, bin string, args ...string) []byte {
	t.Helper()
	p := bStart(t, dir, name, env, bin, args...)
	if p.wait(t, 30*time.Second) != 0 {
		t.Fatal("native command failed", name)
	}
	v, e := os.ReadFile(filepath.Join(dir, name+".stdout"))
	if e != nil {
		t.Fatal(e)
	}
	return v
}
func bFreePort(t *testing.T) string {
	t.Helper()
	l, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer l.Close()
	return fmt.Sprint(l.Addr().(*net.TCPAddr).Port)
}
func bUntil(t *testing.T, d time.Duration, f func() bool, label string) {
	t.Helper()
	end := time.Now().Add(d)
	for time.Now().Before(end) {
		if f() {
			return
		}
		time.Sleep(40 * time.Millisecond)
	}
	t.Fatal("unmet bounded oracle", label)
}
