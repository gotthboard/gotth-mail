package authn

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"forgejo/gotthboard/gotth-mail/internal/store"
	"forgejo/gotthboard/gotth-mail/internal/testpg"
	gotthoidc "github.com/gotthboard/gotth-oidc/pkg/oidc"
)

func TestSQLStoreOIDCStateSingleUseAndSessionPersistence(t *testing.T) {
	db := authnTestDB(t)
	s := SQLStore{DB: db}
	now := time.Unix(100, 0).UTC()
	protected := gotthoidc.ProtectedAttempt{StateHash: sha256.Sum256([]byte("state-1")), ContextCiphertext: "protected-context"}
	protected.NonceCiphertext[0] = 11
	protected.PKCEVerifierCiphertext[0] = 22
	st := LoginAttempt{Protected: protected, BrowserBindingHash: sha256.Sum256([]byte("browser-1")), RedirectAfterLogin: "/", CreatedAt: now, ExpiresAt: now.Add(time.Minute)}
	if err := s.PutAttempt(context.Background(), st); err != nil {
		t.Fatal(err)
	}
	got, err := s.ConsumeAttempt(context.Background(), "state-1", "browser-1", now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if got.Protected != st.Protected || got.UsedAt == nil {
		t.Fatalf("bad consumed state %#v", got)
	}
	if _, err := s.ConsumeAttempt(context.Background(), "state-1", "browser-1", now.Add(2*time.Second)); err != ErrInvalidOIDCState {
		t.Fatalf("second consume err=%v", err)
	}
	if _, err := s.ConsumeAttempt(context.Background(), "state-1", "wrong-browser", now.Add(2*time.Second)); err != ErrInvalidOIDCState {
		t.Fatalf("wrong browser err=%v", err)
	}
	sess := Session{ID: "sess-1", IdentityRefID: "issuer|subject", CSRFSecretHash: "csrf", AuthMethod: "oidc", CreatedAt: now, ExpiresAt: now.Add(time.Hour), LastSeenAt: now}
	if err := s.PutSession(context.Background(), sess); err != nil {
		t.Fatal(err)
	}
	persisted := SQLStore{DB: db}
	loaded, ok := persisted.Session(context.Background(), "sess-1")
	if !ok || loaded.IdentityRefID != sess.IdentityRefID || loaded.AuthMethod != "oidc" {
		t.Fatalf("loaded=%#v ok=%v", loaded, ok)
	}
}

func TestSQLStoreRejectsExpiredState(t *testing.T) {
	db := authnTestDB(t)
	s := SQLStore{DB: db}
	now := time.Unix(200, 0).UTC()
	protected := gotthoidc.ProtectedAttempt{StateHash: sha256.Sum256([]byte("expired")), ContextCiphertext: "protected-context"}
	if err := s.PutAttempt(context.Background(), LoginAttempt{Protected: protected, BrowserBindingHash: sha256.Sum256([]byte("b")), RedirectAfterLogin: "/", CreatedAt: now.Add(-time.Hour), ExpiresAt: now.Add(-time.Minute)}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ConsumeAttempt(context.Background(), "expired", "b", now); err != ErrInvalidOIDCState {
		t.Fatalf("expired consume err=%v", err)
	}
}

func TestSQLStoreAdmitsOneConcurrentAttemptConsumer(t *testing.T) {
	db := authnTestDB(t)
	store := SQLStore{DB: db}
	now := time.Unix(300, 0).UTC()
	protected := gotthoidc.ProtectedAttempt{StateHash: sha256.Sum256([]byte("concurrent-state")), ContextCiphertext: "protected-context"}
	if err := store.PutAttempt(context.Background(), LoginAttempt{Protected: protected, BrowserBindingHash: sha256.Sum256([]byte("browser")), RedirectAfterLogin: "/", CreatedAt: now, ExpiresAt: now.Add(time.Minute)}); err != nil {
		t.Fatal(err)
	}
	var winners atomic.Int32
	var wait sync.WaitGroup
	for range 8 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			if _, err := store.ConsumeAttempt(context.Background(), "concurrent-state", "browser", now.Add(time.Second)); err == nil {
				winners.Add(1)
			}
		}()
	}
	wait.Wait()
	if got := winners.Load(); got != 1 {
		t.Fatalf("concurrent consumers admitted=%d want=1", got)
	}
}

func TestSQLStoreNilDatabaseAndCorruptProtectedFieldsFailClosed(t *testing.T) {
	store := SQLStore{}
	if err := store.PutAttempt(context.Background(), LoginAttempt{}); err == nil {
		t.Fatal("nil database accepted attempt")
	}
	if _, ok := store.Session(context.Background(), "session"); ok {
		t.Fatal("nil database returned session")
	}
	if _, err := store.ConsumeAttempt(context.Background(), "state", "browser", time.Now()); err == nil {
		t.Fatal("nil database consumed attempt")
	}
	if err := store.PutSession(context.Background(), Session{}); err == nil {
		t.Fatal("nil database accepted session")
	}
	var attempt LoginAttempt
	if err := decodeProtectedAttempt(&attempt, make([]byte, 31), make([]byte, 72), make([]byte, 72), make([]byte, 32)); err == nil {
		t.Fatal("corrupt state digest accepted")
	}
}

func authnTestDB(t *testing.T) *sql.DB {
	t.Helper()
	return testpg.DB(t, store.MigrateSQL)
}
