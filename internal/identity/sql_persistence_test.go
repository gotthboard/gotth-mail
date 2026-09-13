package identity

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"sync"
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
	s.Audit = audit.SQLWriter{DB: db}
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
	var publicID, label, verifier string
	if err := db.QueryRow(`SELECT public_id, label, verifier FROM tokens WHERE kind='app_password'`).Scan(&publicID, &label, &verifier); err != nil {
		t.Fatal(err)
	}
	if publicID != created.ID || label != "phone" || verifier == created.SecretOnce || strings.Contains(verifier, created.SecretOnce) {
		t.Fatalf("stored app password contract id=%q label=%q verifier=%q", publicID, label, verifier)
	}
	var createAudits int
	if err := db.QueryRow(`SELECT count(*) FROM audit_events WHERE action='app_password.create' AND result='success'`).Scan(&createAudits); err != nil || createAudits != 1 {
		t.Fatalf("create audits=%d err=%v", createAudits, err)
	}

	restartedDaemon := daemon.Service{}
	restarted, err := NewSQLService(context.Background(), db, "example.test")
	if err != nil {
		t.Fatal(err)
	}
	restarted.Audit = audit.SQLWriter{DB: db}
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
	if got := restartedDaemon.DovecotPassdb("app-use", daemon.PassdbRequest{Username: "user@example.test", Secret: "persisted-client-secret", Protocol: "imap"}); got.Decision != daemon.OK {
		t.Fatalf("daemon app-password auth=%#v", got)
	}
	var useAudits int
	if err := db.QueryRow(`SELECT count(*) FROM audit_events WHERE action='app_password.use' AND correlation_id='app-use' AND result='success'`).Scan(&useAudits); err != nil || useAudits != 1 {
		t.Fatalf("use audits=%d err=%v", useAudits, err)
	}
	listed := restarted.ListAppPasswords("user@example.test")
	if len(listed) != 1 || listed[0].ID != created.ID || listed[0].Label != "phone" {
		t.Fatalf("app password identity/label did not survive restart: %#v", listed)
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
	var revokeAudits int
	if err := db.QueryRow(`SELECT count(*) FROM audit_events WHERE action='app_password.revoke' AND result='success'`).Scan(&revokeAudits); err != nil || revokeAudits != 1 {
		t.Fatalf("revoke audits=%d err=%v", revokeAudits, err)
	}
	restartedAgain, err := NewSQLService(context.Background(), db, "example.test")
	if err != nil {
		t.Fatal(err)
	}
	if restartedAgain.VerifyDovecot("user@example.test", "persisted-client-secret") {
		t.Fatal("revoked app password survived restart as valid")
	}
}

func TestSQLAppPasswordCreateAndRevokeRollBackWithSuccessAudit(t *testing.T) {
	db := identityTestDB(t)
	s, err := NewSQLService(context.Background(), db, "example.test")
	if err != nil {
		t.Fatal(err)
	}
	s.Audit = &audit.MemoryWriter{}
	s.Authorizer = authz.StaticAuthorizer{}
	admin := authz.Actor{Type: "local_admin", ID: "admin"}
	if _, err := s.CreateOrReplaceUser(context.Background(), admin, Mailbox{Email: "user@example.test", Active: true}, "mail-password"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`ALTER TABLE audit_events ADD CONSTRAINT reject_app_password_success CHECK (action NOT LIKE 'app_password.%')`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateAppPassword(context.Background(), admin, "user@example.test", "phone"); err == nil {
		t.Fatal("create committed without its success audit")
	}
	var count int
	if err := db.QueryRow(`SELECT count(*) FROM tokens WHERE kind='app_password'`).Scan(&count); err != nil || count != 0 {
		t.Fatalf("rolled-back create token count=%d err=%v", count, err)
	}
	if _, err := db.Exec(`ALTER TABLE audit_events DROP CONSTRAINT reject_app_password_success`); err != nil {
		t.Fatal(err)
	}
	created, err := s.CreateAppPassword(context.Background(), admin, "user@example.test", "phone")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`ALTER TABLE audit_events ADD CONSTRAINT reject_app_password_success CHECK (action <> 'app_password.revoke')`); err != nil {
		t.Fatal(err)
	}
	if err := s.RevokeAppPassword(context.Background(), admin, "user@example.test", created.ID); err == nil {
		t.Fatal("revoke committed without its success audit")
	}
	var revoked sql.NullTime
	if err := db.QueryRow(`SELECT revoked_at FROM tokens WHERE public_id=$1`, created.ID).Scan(&revoked); err != nil || revoked.Valid {
		t.Fatalf("rolled-back revoke state=%#v err=%v", revoked, err)
	}
	if !s.VerifyDovecot("user@example.test", created.SecretOnce) {
		t.Fatal("rolled-back revoke changed runtime verifier projection")
	}
}

func TestSQLAppPasswordLimitIsConcurrentAndSurvivesRestart(t *testing.T) {
	db := identityTestDB(t)
	seed, err := NewSQLService(context.Background(), db, "example.test")
	if err != nil {
		t.Fatal(err)
	}
	seed.Audit = &audit.MemoryWriter{}
	seed.Authorizer = authz.StaticAuthorizer{}
	admin := authz.Actor{Type: "local_admin", ID: "admin"}
	if _, err := seed.CreateOrReplaceUser(context.Background(), admin, Mailbox{Email: "user@example.test", Active: true}, "mail-password"); err != nil {
		t.Fatal(err)
	}

	services := make([]*Service, MaxActiveAppPasswords+4)
	for i := range services {
		services[i], err = NewSQLService(context.Background(), db, "example.test")
		if err != nil {
			t.Fatal(err)
		}
		services[i].Audit = &audit.MemoryWriter{}
		services[i].Authorizer = authz.StaticAuthorizer{}
	}
	var wg sync.WaitGroup
	errs := make(chan error, len(services))
	for i, service := range services {
		wg.Add(1)
		go func(i int, service *Service) {
			defer wg.Done()
			_, err := service.CreateAppPassword(context.Background(), admin, "user@example.test", fmt.Sprintf("client-%d", i))
			errs <- err
		}(i, service)
	}
	wg.Wait()
	close(errs)
	succeeded, limited := 0, 0
	for err := range errs {
		switch {
		case err == nil:
			succeeded++
		case errors.Is(err, ErrAppPasswordLimit):
			limited++
		default:
			t.Fatalf("unexpected concurrent create error: %v", err)
		}
	}
	if succeeded != MaxActiveAppPasswords || limited != len(services)-MaxActiveAppPasswords {
		t.Fatalf("succeeded=%d limited=%d", succeeded, limited)
	}
	if _, err := NewSQLService(context.Background(), db, "example.test"); err != nil {
		t.Fatalf("bounded state failed restart: %v", err)
	}
}

func TestSQLServiceRejectsPersistedAppPasswordLimitViolation(t *testing.T) {
	db := identityTestDB(t)
	s, err := NewSQLService(context.Background(), db, "example.test")
	if err != nil {
		t.Fatal(err)
	}
	s.Audit = &audit.MemoryWriter{}
	s.Authorizer = authz.StaticAuthorizer{}
	if _, err := s.CreateOrReplaceUser(context.Background(), authz.Actor{Type: "local_admin", ID: "admin"}, Mailbox{Email: "user@example.test", Active: true}, "mail-password"); err != nil {
		t.Fatal(err)
	}
	for i := 0; i <= MaxActiveAppPasswords; i++ {
		publicID := fmt.Sprintf("app_manual_%02d", i)
		if _, err := db.Exec(`INSERT INTO tokens(id, subject_type, subject_id, kind, verifier, label, scope_json, created_at, public_id) VALUES ($1,'mailbox','user@example.test','app_password',$2,$3,'[]',CURRENT_TIMESTAMP,$4)`, stableUUID(publicID), daemon.MakeDjangoPBKDF2SHA256("secret-value", fmt.Sprintf("salt-%d", i), 1200), fmt.Sprintf("client-%d", i), publicID); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := NewSQLService(context.Background(), db, "example.test"); err == nil || !strings.Contains(err.Error(), "exceeds active app password limit") {
		t.Fatalf("startup accepted unbounded verifier state: %v", err)
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
