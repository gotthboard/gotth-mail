package authn

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"fmt"
	"strings"
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
	seedSCIMMailbox(t, db, "scope-a", "scim-user-1", "subject", "member@example.test", true)
	sess := Session{ID: "sess-1", CSRFSecretHash: hashText("csrf-secret"), AuthMethod: "oidc", CreatedAt: now, ExpiresAt: now.Add(time.Hour), LastSeenAt: now}
	sess, err = s.PutIdentitySession(context.Background(), Identity{Issuer: "https://auth.example/application/o/mail/", Subject: "subject", Email: "member@example.test"}, sess)
	if err != nil {
		t.Fatal(err)
	}
	persisted := SQLStore{DB: db}
	loaded, ok := persisted.Session(context.Background(), "sess-1")
	if !ok || loaded.IdentityRefID != sess.IdentityRefID || loaded.AuthMethod != "oidc" {
		t.Fatalf("loaded=%#v ok=%v", loaded, ok)
	}
	bound, ok := persisted.BoundSession(context.Background(), "sess-1", now.Add(time.Minute))
	if !ok || bound.Mailbox != "member@example.test" || bound.Subject != "subject" || !ValidCSRF(bound.Session, "csrf-secret") {
		t.Fatalf("bound=%#v ok=%v", bound, ok)
	}
}

func TestSQLStoreIdentityBindingRejectsMissingDisabledMismatchedAndAmbiguousMailbox(t *testing.T) {
	now := time.Unix(500, 0).UTC()
	tests := []struct {
		name  string
		seed  func(*testing.T, *sql.DB)
		ident Identity
	}{
		{name: "missing", ident: Identity{Issuer: "https://auth.example/", Subject: "missing", Email: "member@example.test"}},
		{name: "disabled", seed: func(t *testing.T, db *sql.DB) {
			seedSCIMMailbox(t, db, "scope-a", "disabled", "subject", "member@example.test", false)
		}, ident: Identity{Issuer: "https://auth.example/", Subject: "subject", Email: "member@example.test"}},
		{name: "email mismatch", seed: func(t *testing.T, db *sql.DB) {
			seedSCIMMailbox(t, db, "scope-a", "mismatch", "subject", "member@example.test", true)
		}, ident: Identity{Issuer: "https://auth.example/", Subject: "subject", Email: "other@example.test"}},
		{name: "ambiguous", seed: func(t *testing.T, db *sql.DB) {
			seedSCIMMailbox(t, db, "scope-a", "ambiguous-a", "subject", "member@example.test", true)
			seedSCIMMailbox(t, db, "scope-b", "ambiguous-b", "subject", "member2@example.test", true)
		}, ident: Identity{Issuer: "https://auth.example/", Subject: "subject", Email: "member@example.test"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			db := authnTestDB(t)
			if test.seed != nil {
				test.seed(t, db)
			}
			store := SQLStore{DB: db}
			_, err := store.PutIdentitySession(context.Background(), test.ident, Session{ID: "rejected", CSRFSecretHash: hashText("csrf"), AuthMethod: "oidc", CreatedAt: now, ExpiresAt: now.Add(time.Hour), LastSeenAt: now})
			if err == nil {
				t.Fatal("invalid identity binding admitted")
			}
			for _, table := range []string{"identity_refs", "sessions", "audit_events"} {
				var count int
				if scanErr := db.QueryRow(`SELECT count(*) FROM ` + table).Scan(&count); scanErr != nil || count != 0 {
					t.Fatalf("%s count=%d err=%v", table, count, scanErr)
				}
			}
		})
	}
}

func TestSQLStoreIdentityBindingCannotMoveSubjectOrShareMailbox(t *testing.T) {
	db := authnTestDB(t)
	seedSCIMMailbox(t, db, "scope-a", "stable-user", "subject-a", "member@example.test", true)
	store := SQLStore{DB: db}
	now := time.Unix(600, 0).UTC()
	session := func(id string) Session {
		return Session{ID: id, CSRFSecretHash: hashText("csrf"), AuthMethod: "oidc", CreatedAt: now, ExpiresAt: now.Add(time.Hour), LastSeenAt: now}
	}
	first, err := store.PutIdentitySession(context.Background(), Identity{Issuer: "https://auth.example/", Subject: "subject-a", Email: "member@example.test"}, session("first"))
	if err != nil {
		t.Fatal(err)
	}
	if first.IdentityRefID == "" {
		t.Fatal("missing durable identity ID")
	}
	if _, err := db.Exec(`UPDATE scim_resources SET external_id='subject-b' WHERE id='stable-user'`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.PutIdentitySession(context.Background(), Identity{Issuer: "https://auth.example/", Subject: "subject-b", Email: "member@example.test"}, session("second")); err == nil {
		t.Fatal("second subject shared an already-bound mailbox")
	}
	if _, ok := store.BoundSession(context.Background(), "first", now.Add(time.Minute)); !ok {
		t.Fatal("existing bound session disappeared")
	}
}

func seedSCIMMailbox(t *testing.T, db *sql.DB, scope, resourceID, externalID, email string, active bool) {
	t.Helper()
	local, domain, ok := strings.Cut(email, "@")
	if !ok {
		t.Fatalf("bad test email %q", email)
	}
	domainID, err := randomUUID()
	if err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`INSERT INTO domains(id,name,enabled,created_at,updated_at) VALUES ($1,$2,true,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP) ON CONFLICT (name) DO UPDATE SET updated_at=EXCLUDED.updated_at RETURNING id::text`, domainID, domain).Scan(&domainID); err != nil {
		t.Fatal(err)
	}
	mailboxID, err := randomUUID()
	if err != nil {
		t.Fatal(err)
	}
	document := fmt.Sprintf(`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"id":%q,"externalId":%q,"userName":%q,"active":%t}`, resourceID, externalID, email, active)
	if _, err := db.Exec(`INSERT INTO scim_resources(scope,resource_type,id,external_id,manager,version,credential_version,created_unix_nano,last_modified_unix_nano,data) VALUES ($1,'User',$2,$3,'','v1','',1,1,$4)`, scope, resourceID, externalID, []byte(document)); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO mailboxes(id,domain_id,local_part,display_name,enabled,created_at,updated_at,scim_resource_id) VALUES ($1,$2,$3,'Member',$4,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP,$5)`, mailboxID, domainID, local, active, resourceID); err != nil {
		t.Fatal(err)
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
