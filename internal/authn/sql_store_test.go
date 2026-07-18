package authn

import (
	"context"
	"database/sql"
	"net"
	"path/filepath"
	"testing"
	"time"

	"forgejo/linus/gophermailforge/internal/store"
	embeddedpostgres "github.com/fergusstrange/embedded-postgres"
	_ "github.com/lib/pq"
)

func TestSQLStoreOIDCStateSingleUseAndSessionPersistence(t *testing.T) {
	db := authnTestDB(t)
	s := SQLStore{DB: db}
	now := time.Unix(100, 0).UTC()
	st := LoginState{StateID: "state-1", Nonce: "nonce-1", BrowserBindingHash: "browser-1", RedirectAfterLogin: "/", CreatedAt: now, ExpiresAt: now.Add(time.Minute)}
	if err := s.PutState(st); err != nil {
		t.Fatal(err)
	}
	got, err := s.consumeState("state-1", "browser-1", now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if got.Nonce != st.Nonce || got.UsedAt == nil {
		t.Fatalf("bad consumed state %#v", got)
	}
	if _, err := s.consumeState("state-1", "browser-1", now.Add(2*time.Second)); err != ErrInvalidOIDCState {
		t.Fatalf("second consume err=%v", err)
	}
	if _, err := s.consumeState("state-1", "wrong-browser", now.Add(2*time.Second)); err != ErrInvalidOIDCState {
		t.Fatalf("wrong browser err=%v", err)
	}
	sess := Session{ID: "sess-1", IdentityRefID: "issuer|subject", CSRFSecretHash: "csrf", AuthMethod: "oidc", CreatedAt: now, ExpiresAt: now.Add(time.Hour), LastSeenAt: now}
	if err := s.putSession(sess); err != nil {
		t.Fatal(err)
	}
	persisted := SQLStore{DB: db}
	loaded, ok := persisted.Session("sess-1")
	if !ok || loaded.IdentityRefID != sess.IdentityRefID || loaded.AuthMethod != "oidc" {
		t.Fatalf("loaded=%#v ok=%v", loaded, ok)
	}
}

func TestSQLStoreRejectsExpiredState(t *testing.T) {
	db := authnTestDB(t)
	s := SQLStore{DB: db}
	now := time.Unix(200, 0).UTC()
	if err := s.PutState(LoginState{StateID: "expired", Nonce: "n", BrowserBindingHash: "b", CreatedAt: now.Add(-time.Hour), ExpiresAt: now.Add(-time.Minute)}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.consumeState("expired", "b", now); err != ErrInvalidOIDCState {
		t.Fatalf("expired consume err=%v", err)
	}
}

func authnTestDB(t *testing.T) *sql.DB {
	t.Helper()
	port := authnFreePort(t)
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

func authnFreePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}
