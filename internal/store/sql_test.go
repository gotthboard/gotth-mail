package store

import (
	"context"
	"database/sql"
	"testing"

	_ "modernc.org/sqlite"
)

func TestMigrateSQLOnEmptyDatabase(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`PRAGMA foreign_keys = ON`); err != nil {
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
	if _, err := db.Exec(`INSERT INTO domains(id, name, created_at, updated_at) VALUES ('d1', 'example.test', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO domains(id, name, created_at, updated_at) VALUES ('d2', 'example.test', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)`); err == nil {
		t.Fatal("expected unique domain constraint")
	}
	if _, err := db.Exec(`INSERT INTO mailboxes(id, domain_id, local_part, created_at, updated_at) VALUES ('m1', 'missing', 'postmaster', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)`); err == nil {
		t.Fatal("expected mailbox foreign-key constraint")
	}
}
