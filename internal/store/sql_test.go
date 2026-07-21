package store

import (
	"context"
	"testing"

	"forgejo/linus/gophermailforge/internal/audit"
	"forgejo/linus/gophermailforge/internal/testpg"
)

func TestMigrateSQLOnPostgres(t *testing.T) {
	db := testpg.DB(t, MigrateSQL)
	var count int
	if err := db.QueryRow(`SELECT count(*) FROM schema_migrations`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	wantMigrations := len(InitialSchema) + len(upgradeMigrations)
	if count != wantMigrations {
		t.Fatalf("schema_migrations=%d want %d", count, wantMigrations)
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
	if _, err := db.Exec(`INSERT INTO tokens(id, subject_type, subject_id, kind, verifier, label, scope_json, created_at) VALUES ($1,'plugin','stub','garbage','v','l','{}',CURRENT_TIMESTAMP)`, "00000000-0000-0000-0000-000000000004"); err == nil {
		t.Fatal("expected token kind check constraint")
	}
	if _, err := db.Exec(`INSERT INTO plugin_registrations(id, name, seam, image, endpoint, enabled, created_at, updated_at) VALUES ($1,'stub','dns','img','ep',true,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)`, "00000000-0000-0000-0000-000000000005"); err == nil {
		t.Fatal("expected enabled plugin credential constraint")
	}
	if _, err := db.Exec(`INSERT INTO oidc_login_states(state_id, nonce, browser_binding_hash, redirect_after_login, created_at, expires_at) VALUES ('s','n','b','/',CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO sessions(id, identity_ref_id, csrf_secret_hash, auth_method, created_at, expires_at, last_seen_at) VALUES ('sess','authentik|sub','csrf','oidc',CURRENT_TIMESTAMP,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO webmail_drafts(id, mailbox, to_addr, subject, body_text, signing_fingerprint, state, created_at, updated_at) VALUES ('draft-a','user@example.test','to@example.test','s','b','fp','draft',CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO webmail_drafts(id, mailbox, to_addr, subject, body_text, signing_fingerprint, state, created_at, updated_at) VALUES ('draft-b','user@example.test','to@example.test','s','b','fp','garbage',CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)`); err == nil {
		t.Fatal("expected draft state check constraint")
	}
	aw := audit.SQLWriter{DB: db}
	if err := aw.Write(context.Background(), audit.Event{Actor: audit.ActorRef{Type: "local_admin", ID: "test"}, Source: &audit.RequestSource{IP: "127.0.0.1", UserAgent: "test-agent"}, Action: "config.apply", Resource: audit.ResourceRef{Type: "generated_config_set", ID: "abc"}, BeforeRedacted: map[string]any{"token": "secret"}, Result: "success"}); err != nil {
		t.Fatal(err)
	}
	var ip, ua, before string
	if err := db.QueryRow(`SELECT source_ip, source_user_agent, before_redacted_json FROM audit_events WHERE action='config.apply'`).Scan(&ip, &ua, &before); err != nil {
		t.Fatal(err)
	}
	if ip != "127.0.0.1" || ua != "test-agent" || before == "" {
		t.Fatalf("bad audit persistence ip=%q ua=%q before=%q", ip, ua, before)
	}
}
