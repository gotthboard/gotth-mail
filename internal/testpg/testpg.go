package testpg

import (
	"context"
	"database/sql"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"testing"
	"time"

	_ "github.com/lib/pq"
)

// VersionEnv optionally declares the exact SQL server_version_num for this test lane.
// Unset retains ordinary developer behavior; a present declaration is fail-closed.
const VersionEnv = "GOTTH_MAIL_TEST_POSTGRES_VERSION"
const legacyVersionEnv = "GOTTH_MAIL_TEST_PG_VERSION_NUM"

// DB creates a private fixture, attesting a declared version before migration.
// Complexity: for a successful call, time O(E+L+S+Q+M), Omega(E+L+S+Q+M),
// tight Theta(E+L+S+Q+M), where E is declaration length, L executable lookup,
// S fixture startup/readiness, Q the optional SQL version query, M migration cost.
// These delegated costs are not constant-time claims. Early failures have time
// O(E+L+S+Q+M), Omega(1); no uniform tight Theta bound is established.
// Auxiliary space O(E+A), Omega(1); tight Theta is not established because A
// includes delegated process/SQL/migration memory. The returned live cluster and
// registered shutdown also have delegated storage/lifecycle costs, not O(1).
func DB(t *testing.T, migrate func(context.Context, *sql.DB) error) *sql.DB {
	return database(t, migrate, false)
}

// MigrationDB returns the dedicated migrator connection for migration-runner
// tests; ordinary package tests retain the historical installer connection.
func MigrationDB(t *testing.T, migrate func(context.Context, *sql.DB) error) *sql.DB {
	return database(t, migrate, true)
}

// RuntimeDB composes the exact shipped fresh or upgrade bootstrap with the
// product prefix runner, candidate runner, migration-pool close, app identity,
// and actual current-schema validator. The installer is retained only for
// setup/oracle work and is never returned to the writer under test.
func RuntimeDB(t *testing.T, lane string, through, migrate func(context.Context, *sql.DB) error, validate func(context.Context, *sql.Tx) error) *sql.DB {
	t.Helper()
	if lane != "fresh" && lane != "upgrade" {
		t.Fatalf("unsupported runtime fixture lane %q", lane)
	}
	admin, port := startDatabase(t, "gotth_mail_installer")
	if lane == "fresh" {
		execScript(t, admin, "bootstrap-migration-authority-fresh.sql")
		if _, err := admin.Exec("SET password_encryption='scram-sha-256'; ALTER ROLE gotth_mail_app PASSWORD 'runtime-fixture-app'; ALTER ROLE gotth_mail_migrator PASSWORD 'runtime-fixture-migrator'"); err != nil {
			t.Fatalf("provision fresh SCRAM verifiers: %v", err)
		}
		execScript(t, admin, "bootstrap-migration-authority-fresh.sql")
	} else {
		if _, err := admin.Exec("CREATE ROLE gotth_mail LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS CONNECTION LIMIT -1; ALTER DATABASE gotth_mail OWNER TO gotth_mail"); err != nil {
			t.Fatalf("create exact legacy owner: %v", err)
		}
	}
	prefixUser := "gotth_mail_migrator"
	if lane == "upgrade" {
		prefixUser = "gotth_mail"
	}
	prefix, err := sql.Open("postgres", fmt.Sprintf("postgres://%s@127.0.0.1:%d/gotth_mail?sslmode=disable", prefixUser, port))
	if err != nil {
		t.Fatal(err)
	}
	prefix.SetMaxOpenConns(1)
	prefix.SetMaxIdleConns(1)
	if err := through(context.Background(), prefix); err != nil {
		_ = prefix.Close()
		t.Fatalf("migrate through 0020: %v", err)
	}
	if err := prefix.Close(); err != nil {
		t.Fatalf("close prefix migration database: %v", err)
	}
	if lane == "fresh" {
		execScript(t, admin, "bootstrap-migration-authority-fresh-0020.sql")
	} else {
		execScript(t, admin, "bootstrap-migration-authority-upgrade-0020.sql")
		if _, err := admin.Exec("SET password_encryption='scram-sha-256'; ALTER ROLE gotth_mail_app PASSWORD 'runtime-upgrade-app'; ALTER ROLE gotth_mail_migrator PASSWORD 'runtime-upgrade-migrator'"); err != nil {
			t.Fatalf("provision upgrade SCRAM verifiers: %v", err)
		}
		var dataDirectory string
		if err := admin.QueryRow("SHOW data_directory").Scan(&dataDirectory); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dataDirectory, "pg_hba.conf"), []byte("local all all trust\nhost all all 127.0.0.1/32 scram-sha-256\nhost all all ::1/128 scram-sha-256\n"), 0600); err != nil {
			t.Fatal(err)
		}
		var reloaded bool
		if err := admin.QueryRow("SELECT pg_reload_conf()").Scan(&reloaded); err != nil || !reloaded {
			t.Fatalf("reload password-authenticated upgrade HBA ok=%v err=%v", reloaded, err)
		}
	}
	migrationURL := fmt.Sprintf("postgres://gotth_mail_migrator@127.0.0.1:%d/gotth_mail?sslmode=disable", port)
	if lane == "upgrade" {
		migrationURL = fmt.Sprintf("postgres://gotth_mail_migrator:runtime-upgrade-migrator@127.0.0.1:%d/gotth_mail?sslmode=disable", port)
	}
	migrator, err := sql.Open("postgres", migrationURL)
	if err != nil {
		t.Fatal(err)
	}
	migrator.SetMaxOpenConns(1)
	migrator.SetMaxIdleConns(1)
	if err := migrate(context.Background(), migrator); err != nil {
		t.Fatalf("candidate migration: %v", err)
	}
	if err := migrator.Close(); err != nil {
		t.Fatalf("close migration database: %v", err)
	}
	appURL := fmt.Sprintf("postgres://gotth_mail_app@127.0.0.1:%d/gotth_mail?sslmode=disable", port)
	if lane == "upgrade" {
		appURL = fmt.Sprintf("postgres://gotth_mail_app:runtime-upgrade-app@127.0.0.1:%d/gotth_mail?sslmode=disable", port)
	}
	app, err := sql.Open("postgres", appURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = app.Close() })
	var sessionUser, currentUser string
	if err := app.QueryRow("SELECT session_user::text,current_user::text").Scan(&sessionUser, &currentUser); err != nil {
		t.Fatal(err)
	}
	if sessionUser != "gotth_mail_app" || currentUser != "gotth_mail_app" {
		t.Fatalf("runtime identity=%s/%s", sessionUser, currentUser)
	}
	tx, err := app.BeginTx(context.Background(), &sql.TxOptions{ReadOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := validate(context.Background(), tx); err != nil {
		_ = tx.Rollback()
		t.Fatalf("validate current schema: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	return app
}

// AuthorityDB starts a distinct installer with no product or legacy roles.
// It is reserved for live bootstrap/credential refusal tests.
func AuthorityDB(t *testing.T) *sql.DB {
	t.Helper()
	db, _ := startDatabase(t, "gotth_mail_installer")
	return db
}

func execScript(t *testing.T, db *sql.DB, name string) {
	t.Helper()
	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate testpg source")
	}
	script, err := os.ReadFile(filepath.Join(filepath.Dir(source), "..", "..", "scripts", name))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(string(script)); err != nil {
		t.Fatalf("exact %s: %v", name, err)
	}
}

func database(t *testing.T, migrate func(context.Context, *sql.DB) error, returnMigration bool) *sql.DB {
	t.Helper()
	db, port := startDatabase(t, "gotth_mail")
	if _, err := db.Exec(`
CREATE ROLE gotth_mail_schema_owner NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;
CREATE ROLE gotth_mail_migrator LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;
CREATE ROLE gotth_mail_app LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;
CREATE ROLE gotth_mail_gate LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;
CREATE ROLE gotth_mail_jobs LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;
CREATE ROLE gotth_mail_import LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;
CREATE ROLE gotth_mail_scim LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;
GRANT gotth_mail_schema_owner TO gotth_mail_migrator WITH ADMIN FALSE, INHERIT FALSE, SET TRUE;
GRANT CONNECT ON DATABASE gotth_mail TO gotth_mail_migrator,gotth_mail_app;
GRANT CREATE ON DATABASE gotth_mail TO gotth_mail_schema_owner;
GRANT USAGE,CREATE ON SCHEMA public TO gotth_mail_schema_owner;
REVOKE CREATE ON SCHEMA public FROM gotth_mail_app,PUBLIC;
ALTER ROLE gotth_mail_migrator IN DATABASE gotth_mail SET role TO 'gotth_mail_schema_owner';`); err != nil {
		t.Fatalf("migration authority bootstrap: %v", err)
	}
	migrationDSN := fmt.Sprintf("postgres://gotth_mail_migrator@127.0.0.1:%d/gotth_mail?sslmode=disable", port)
	migrationDB, err := sql.Open("postgres", migrationDSN)
	if err != nil {
		t.Fatal(err)
	}
	migrationDB.SetMaxOpenConns(1)
	migrationDB.SetMaxIdleConns(1)
	t.Cleanup(func() { _ = migrationDB.Close() })
	if err := migrationDB.Ping(); err != nil {
		t.Fatal(err)
	}
	if migrate != nil {
		if err := migrate(context.Background(), migrationDB); err != nil {
			t.Fatal(err)
		}
	}
	migrationDB.SetMaxOpenConns(0)
	migrationDB.SetMaxIdleConns(2)
	if returnMigration {
		return migrationDB
	}
	return db
}

func startDatabase(t *testing.T, superuser string) (*sql.DB, int) {
	t.Helper()
	raw, declared := os.LookupEnv(legacyVersionEnv)
	envName := legacyVersionEnv
	if !declared {
		raw, declared = os.LookupEnv(VersionEnv)
		envName = VersionEnv
	}
	var expected uint64
	if declared {
		var err error
		expected, err = strconv.ParseUint(raw, 10, 31)
		if err != nil || expected == 0 {
			t.Fatalf("invalid %s: expected decimal SQL version 1..2147483647", envName)
		}
	}
	initdb, err := exec.LookPath("initdb")
	if err != nil {
		if declared {
			t.Fatal("declared PostgreSQL lane requires initdb")
		}
		t.Skip("local initdb not available")
	}
	postgres, err := exec.LookPath("postgres")
	if err != nil {
		if declared {
			t.Fatal("declared PostgreSQL lane requires postgres")
		}
		t.Skip("local postgres not available")
	}
	createdb, err := exec.LookPath("createdb")
	if err != nil {
		if declared {
			t.Fatal("declared PostgreSQL lane requires createdb")
		}
		t.Skip("local createdb not available")
	}
	port := freePort(t)
	root, err := os.MkdirTemp("", "gotth-pg-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	data := filepath.Join(root, "data")
	socketDir := filepath.Join(root, "runtime")
	if err := os.MkdirAll(socketDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command(initdb, "-A", "trust", "-U", superuser, "-D", data).CombinedOutput(); err != nil {
		t.Fatalf("initdb: %v\n%s", err, out)
	}
	cmd := exec.Command(postgres, "-D", data, "-h", "127.0.0.1", "-p", fmt.Sprint(port), "-k", socketDir, "-c", "shared_memory_type=mmap", "-c", "dynamic_shared_memory_type=mmap", "-c", "max_prepared_transactions=10")
	if err := cmd.Start(); err != nil {
		t.Fatalf("postgres start: %v", err)
	}
	t.Cleanup(func() {
		if err := cmd.Process.Signal(os.Interrupt); err != nil {
			_ = cmd.Process.Kill()
		}
		done := make(chan struct{})
		go func() { _ = cmd.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			_ = cmd.Process.Kill()
			<-done
		}
	})
	adminDSN := fmt.Sprintf("postgres://%s@127.0.0.1:%d/postgres?sslmode=disable", superuser, port)
	waitSQL(t, adminDSN)
	if out, err := exec.Command(createdb, "-h", "127.0.0.1", "-p", fmt.Sprint(port), "-U", superuser, "gotth_mail").CombinedOutput(); err != nil {
		t.Fatalf("createdb: %v\n%s", err, out)
	}
	db, err := sql.Open("postgres", fmt.Sprintf("postgres://%s@127.0.0.1:%d/gotth_mail?sslmode=disable", superuser, port))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.Ping(); err != nil {
		t.Fatal(err)
	}
	if declared {
		var actual uint64
		if err := db.QueryRow("SHOW server_version_num").Scan(&actual); err != nil {
			t.Fatalf("PostgreSQL version attestation failed: %v", err)
		}
		t.Logf("PostgreSQL lane expected=%d actual=%d", expected, actual)
		if actual != expected {
			t.Fatalf("PostgreSQL version mismatch: expected=%d actual=%d", expected, actual)
		}
	}
	return db, port
}

func waitSQL(t *testing.T, dsn string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	var last error
	for time.Now().Before(deadline) {
		db, err := sql.Open("postgres", dsn)
		if err == nil {
			last = db.Ping()
			_ = db.Close()
			if last == nil {
				return
			}
		} else {
			last = err
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("postgres did not become ready: %v", last)
}

func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}
