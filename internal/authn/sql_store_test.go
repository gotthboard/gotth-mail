package authn

import (
	"database/sql"
	"testing"
	"time"

	"forgejo/gotthboard/gotth-mail/internal/store"
	"forgejo/gotthboard/gotth-mail/internal/testpg"
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
	return testpg.DB(t, store.MigrateSQL)
}
