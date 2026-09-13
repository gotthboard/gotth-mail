package testpg

import (
	"context"
	"database/sql"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	_ "github.com/lib/pq"
)

func DB(t *testing.T, migrate func(context.Context, *sql.DB) error) *sql.DB {
	t.Helper()
	initdb, err := exec.LookPath("initdb")
	if err != nil {
		t.Skip("local initdb not available")
	}
	postgres, err := exec.LookPath("postgres")
	if err != nil {
		t.Skip("local postgres not available")
	}
	createdb, err := exec.LookPath("createdb")
	if err != nil {
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
	cmd := exec.Command(postgres, "-D", data, "-h", "127.0.0.1", "-p", fmt.Sprint(port), "-k", runtime)
	if err := cmd.Start(); err != nil {
		t.Fatalf("postgres start: %v", err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
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
