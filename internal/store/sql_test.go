package store

import (
	"context"
	"database/sql"
	"net"
	"path/filepath"
	"testing"
	"time"

	embeddedpostgres "github.com/fergusstrange/embedded-postgres"
	_ "github.com/lib/pq"
)

func TestMigrateSQLOnEmbeddedPostgres(t *testing.T) {
	port := freePort(t)
	root := t.TempDir()
	cfg := embeddedpostgres.DefaultConfig().
		Username("gmf").
		Password("gmf-dev-only").
		Database("gophermailforge").
		Port(uint32(port)).
		DataPath(filepath.Join(root, "data")).
		RuntimePath(filepath.Join(root, "runtime")).
		CachePath(filepath.Join(root, "cache")).
		StartTimeout(30 * time.Second)
	pg := embeddedpostgres.NewDatabase(cfg)
	if err := pg.Start(); err != nil {
		t.Fatalf("start embedded postgres: %v", err)
	}
	t.Cleanup(func() { _ = pg.Stop() })

	db, err := sql.Open("postgres", cfg.GetConnectionURL()+"?sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Ping(); err != nil {
		t.Fatal(err)
	}
	if err := MigrateSQL(context.Background(), db); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := db.QueryRow(`SELECT count(*) FROM schema_migrations`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != len(InitialSchema) {
		t.Fatalf("schema_migrations=%d want %d", count, len(InitialSchema))
	}
	if _, err := db.Exec(`INSERT INTO domains(id, name, created_at, updated_at) VALUES ($1, $2, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)`, "00000000-0000-0000-0000-000000000001", "example.test"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO domains(id, name, created_at, updated_at) VALUES ($1, $2, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)`, "00000000-0000-0000-0000-000000000002", "example.test"); err == nil {
		t.Fatal("expected unique domain constraint")
	}
	if _, err := db.Exec(`INSERT INTO mailboxes(id, domain_id, local_part, created_at, updated_at) VALUES ($1, $2, $3, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)`, "00000000-0000-0000-0000-000000000003", "00000000-0000-0000-0000-000000009999", "postmaster"); err == nil {
		t.Fatal("expected mailbox foreign-key constraint")
	}
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
