package testpg

import (
	"context"
	"database/sql"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	_ "github.com/lib/pq"
)

// VersionEnv optionally declares the exact SQL server_version_num for this test lane.
// Unset retains ordinary developer behavior; a present declaration is fail-closed.
const VersionEnv = "GOTTH_MAIL_TEST_PG_VERSION_NUM"

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
	t.Helper()
	raw, declared := os.LookupEnv(VersionEnv)
	var expected uint64
	if declared {
		var err error
		expected, err = strconv.ParseUint(raw, 10, 31)
		if err != nil || expected == 0 {
			t.Fatalf("invalid %s: expected decimal SQL version 1..2147483647", VersionEnv)
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
	root := t.TempDir()
	data := filepath.Join(root, "data")
	runtime := filepath.Join(root, "runtime")
	if err := os.MkdirAll(runtime, 0o700); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command(initdb, "-A", "trust", "-U", "gotth_mail", "-D", data).CombinedOutput(); err != nil {
		t.Fatalf("initdb: %v\n%s", err, out)
	}
	cmd := exec.Command(postgres, "-D", data, "-h", "127.0.0.1", "-p", fmt.Sprint(port), "-k", runtime,
		"-c", "shared_memory_type=mmap", "-c", "dynamic_shared_memory_type=mmap")
	if err := cmd.Start(); err != nil {
		t.Fatalf("postgres start: %v", err)
	}
	t.Cleanup(func() {
		if err := cmd.Process.Signal(os.Interrupt); err != nil {
			_ = cmd.Process.Kill()
		}
		done := make(chan struct{})
		go func() {
			_ = cmd.Wait()
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			_ = cmd.Process.Kill()
			<-done
		}
	})
	dsn := fmt.Sprintf("postgres://gotth_mail@127.0.0.1:%d/gotth_mail?sslmode=disable", port)
	adminDSN := fmt.Sprintf("postgres://gotth_mail@127.0.0.1:%d/postgres?sslmode=disable", port)
	waitSQL(t, adminDSN)
	if out, err := exec.Command(createdb, "-h", "127.0.0.1", "-p", fmt.Sprint(port), "-U", "gotth_mail", "gotth_mail").CombinedOutput(); err != nil {
		t.Fatalf("createdb: %v\n%s", err, out)
	}
	db, err := sql.Open("postgres", dsn)
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
	if migrate != nil {
		if err := migrate(context.Background(), db); err != nil {
			t.Fatal(err)
		}
	}
	return db
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
