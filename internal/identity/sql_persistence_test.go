package identity

import (
	"context"
	"database/sql"
	"net"
	"path/filepath"
	"testing"
	"time"

	"forgejo/linus/gophermailforge/internal/audit"
	"forgejo/linus/gophermailforge/internal/authz"
	"forgejo/linus/gophermailforge/internal/daemon"
	"forgejo/linus/gophermailforge/internal/store"
	embeddedpostgres "github.com/fergusstrange/embedded-postgres"
	_ "github.com/lib/pq"
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

func identityTestDB(t *testing.T) *sql.DB {
	t.Helper()
	port := identityFreePort(t)
	root := t.TempDir()
	cfg := embeddedpostgres.DefaultConfig().Username("gmf").Password("gmf-dev-only").Database("gophermailforge").Port(uint32(port)).DataPath(filepath.Join(root, "data")).RuntimePath(filepath.Join(root, "runtime")).CachePath(filepath.Join(root, "cache")).StartTimeout(30 * time.Second)
	pg := embeddedpostgres.NewDatabase(cfg)
	if err := pg.Start(); err != nil {
		t.Fatalf("start embedded postgres: %v", err)
	}
	t.Cleanup(func() { _ = pg.Stop() })
	db, err := sql.Open("postgres", cfg.GetConnectionURL()+"?sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.Ping(); err != nil {
		t.Fatal(err)
	}
	if err := store.MigrateSQL(context.Background(), db); err != nil {
		t.Fatal(err)
	}
	return db
}

func identityFreePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}
