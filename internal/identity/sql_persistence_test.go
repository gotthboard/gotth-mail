package identity

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"forgejo/gotthboard/gotth-mail/internal/audit"
	"forgejo/gotthboard/gotth-mail/internal/authz"
	"forgejo/gotthboard/gotth-mail/internal/daemon"
	"forgejo/gotthboard/gotth-mail/internal/store"
	"forgejo/gotthboard/gotth-mail/internal/testpg"
)

func TestSQLServicePersistsMailboxAppPasswordAndTokensAcrossRestart(t *testing.T) {
	db := identityTestDB(t)
	d := daemon.Service{}
	s, err := NewSQLService(context.Background(), db, "example.test")
	if err != nil {
		t.Fatal(err)
	}
	s.Audit = &audit.MemoryWriter{}
	s.Authorizer = authz.StaticAuthorizer{}
	s.Daemon = &d
	s.Now = func() time.Time { return time.Unix(1000, 0).UTC() }
	s.Secret = func() (string, error) { return "persisted-client-secret", nil }
	admin := authz.Actor{Type: "local_admin", ID: "admin"}
	if _, err := s.CreateOrReplaceUser(context.Background(), admin, Mailbox{Email: "user@example.test", DisplayName: "User", Active: true}, "mail-password"); err != nil {
		t.Fatal(err)
	}
	created, err := s.CreateAppPassword(context.Background(), admin, "user@example.test", "phone")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.AddTokenWithScopes("api-token", "api_token", "api-secret-token", "mailbox:user@example.test:mailbox:app_password.read"); err != nil {
		t.Fatal(err)
	}
	if !s.VerifyDovecot("user@example.test", "persisted-client-secret") {
		t.Fatal("app password not valid before restart")
	}

	restartedDaemon := daemon.Service{}
	restarted, err := NewSQLService(context.Background(), db, "example.test")
	if err != nil {
		t.Fatal(err)
	}
	restarted.Audit = &audit.MemoryWriter{}
	restarted.Authorizer = authz.StaticAuthorizer{}
	restarted.Daemon = &restartedDaemon
	if err := restarted.loadSQL(context.Background()); err != nil {
		t.Fatal(err)
	}
	m, ok := restarted.GetUser("user@example.test")
	if !ok || m.DisplayName != "User" || !m.Active {
		t.Fatalf("mailbox after restart %#v ok=%v", m, ok)
	}
	if !restarted.VerifyDovecot("user@example.test", "mail-password") {
		t.Fatal("mailbox password not valid after restart")
	}
	if !restarted.VerifyDovecot("user@example.test", "persisted-client-secret") {
		t.Fatal("app password not valid after restart")
	}
	actor, err := restarted.AuthenticateBearer("Bearer api-secret-token", "api_token")
	if err != nil {
		t.Fatal(err)
	}
	if actor.ID != "api-token" || len(actor.Scopes) != 1 || actor.Scopes[0] != "mailbox:user@example.test:mailbox:app_password.read" {
		t.Fatalf("actor=%#v", actor)
	}
	if err := restarted.RevokeAppPassword(context.Background(), admin, "user@example.test", created.ID); err != nil {
		t.Fatal(err)
	}
	restartedAgain, err := NewSQLService(context.Background(), db, "example.test")
	if err != nil {
		t.Fatal(err)
	}
	if restartedAgain.VerifyDovecot("user@example.test", "persisted-client-secret") {
		t.Fatal("revoked app password survived restart as valid")
	}
}

func TestSQLServiceLoadsEnabledDomainPolicy(t *testing.T) {
	db := identityTestDB(t)
	emptyService, err := NewSQLService(context.Background(), db)
	if err != nil {
		t.Fatal(err)
	}
	if err := emptyService.ValidateMailbox("user@unmanaged.test"); err == nil {
		t.Fatal("empty durable domain policy admitted an unmanaged domain")
	}
	if _, err := db.Exec(`INSERT INTO domains(id, name, enabled, created_at, updated_at) VALUES ($1,$2,true,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP),($3,$4,false,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)`,
		"00000000-0000-4000-8000-000000000701", "example.test",
		"00000000-0000-4000-8000-000000000702", "disabled.test"); err != nil {
		t.Fatal(err)
	}
	service, err := NewSQLService(context.Background(), db)
	if err != nil {
		t.Fatal(err)
	}
	if err := service.ValidateMailbox("user@example.test"); err != nil {
		t.Fatalf("enabled persisted domain rejected: %v", err)
	}
	for _, address := range []string{"user@disabled.test", "user@unmanaged.test"} {
		if err := service.ValidateMailbox(address); err == nil {
			t.Fatalf("mailbox outside enabled durable domain policy accepted: %s", address)
		}
	}
}

func identityTestDB(t *testing.T) *sql.DB {
	t.Helper()
	return testpg.DB(t, store.MigrateSQL)
}
