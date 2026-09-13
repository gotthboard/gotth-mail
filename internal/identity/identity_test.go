package identity

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"forgejo/gotthboard/gotth-mail/internal/audit"
	"forgejo/gotthboard/gotth-mail/internal/authz"
	"forgejo/gotthboard/gotth-mail/internal/daemon"
)

func testService() *Service {
	s := NewService("example.test")
	s.Audit = &audit.MemoryWriter{}
	s.Authorizer = authz.StaticAuthorizer{Mappings: []authz.RoleMapping{{AuthentikGroup: "managers", Role: authz.RoleDomainManager, Domain: "example.test", Verified: true}}}
	s.Now = func() time.Time { return time.Date(2026, 7, 16, 12, 0, 0, 0, time.UTC) }
	s.Secret = func() (string, error) { return "generated-client-secret", nil }
	return s
}

func TestSCIMCreatePatchDisableAndAudit(t *testing.T) {
	s := testService()
	actor := authz.Actor{Type: "oidc_subject", ID: "u", Groups: []string{"managers"}}
	m, err := s.CreateOrReplaceUser(context.Background(), actor, Mailbox{Email: "user@example.test", DisplayName: "User", Active: true}, "correct horse")
	if err != nil {
		t.Fatal(err)
	}
	if m.ID != "user@example.test" || !m.Active || !strings.HasPrefix(m.Verifier, "pbkdf2_sha256$") {
		t.Fatalf("mailbox=%#v", m)
	}
	if !s.VerifyDovecot("user@example.test", "correct horse") {
		t.Fatal("dovecot verifier did not accept mailbox password")
	}
	m, err = s.PatchUser(context.Background(), actor, "user@example.test", []PatchOperation{{Op: "replace", Path: "/displayName", Value: "Renamed"}, {Op: "replace", Path: "/active", Value: false}})
	if err != nil {
		t.Fatal(err)
	}
	if m.DisplayName != "Renamed" || m.Active {
		t.Fatalf("patched=%#v", m)
	}
	m, err = s.DisableUser(context.Background(), actor, "user@example.test")
	if err != nil {
		t.Fatal(err)
	}
	if m.Active {
		t.Fatal("delete did not disable")
	}
	w := s.Audit.(*audit.MemoryWriter)
	if len(w.Events) < 3 {
		t.Fatalf("missing audit events %#v", w.Events)
	}
}

func TestSCIMRejectsPolicyAndPatchFailures(t *testing.T) {
	s := testService()
	actor := authz.Actor{Type: "oidc_subject", ID: "u", Groups: []string{"managers"}}
	bad := []struct {
		name     string
		m        Mailbox
		password string
	}{{"bad email", Mailbox{Email: "not-mail", Active: true}, "longenough"}, {"bad domain", Mailbox{Email: "user@evil.test", Active: true}, "longenough"}, {"bad password", Mailbox{Email: "user@example.test", Active: true}, "short"}}
	for _, tc := range bad {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := s.CreateOrReplaceUser(context.Background(), actor, tc.m, tc.password); err == nil {
				t.Fatal("accepted bad user")
			}
		})
	}
	if _, err := s.CreateOrReplaceUser(context.Background(), actor, Mailbox{Email: "user@example.test", Active: true}, "longenough"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.PatchUser(context.Background(), actor, "user@example.test", []PatchOperation{{Op: "replace", Path: "/active", Value: "yes"}}); err == nil {
		t.Fatal("accepted scalar active")
	}
	if _, err := s.PatchUser(context.Background(), actor, "user@example.test", []PatchOperation{{Op: "replace", Path: "/unknown", Value: "x"}}); err == nil {
		t.Fatal("accepted unknown path")
	}
}

func TestAppPasswordsSecretOnceRevokeAndVerifier(t *testing.T) {
	s := testService()
	actor := authz.Actor{Type: "oidc_subject", ID: "u", Groups: []string{"managers"}}
	if _, err := s.CreateOrReplaceUser(context.Background(), actor, Mailbox{Email: "user@example.test", Active: true}, "mail-pass-1"); err != nil {
		t.Fatal(err)
	}
	created, err := s.CreateAppPassword(context.Background(), actor, "user@example.test", "phone")
	if err != nil {
		t.Fatal(err)
	}
	if created.SecretOnce != "generated-client-secret" {
		t.Fatalf("secret=%q", created.SecretOnce)
	}
	listed := s.ListAppPasswords("user@example.test")
	if len(listed) != 1 || listed[0].Verifier == "generated-client-secret" || !strings.HasPrefix(listed[0].Verifier, "pbkdf2_sha256$") {
		t.Fatalf("listed=%#v", listed)
	}
	if !s.VerifyDovecot("user@example.test", "generated-client-secret") {
		t.Fatal("app password did not verify")
	}
	if err := s.RevokeAppPassword(context.Background(), actor, "user@example.test", created.ID); err != nil {
		t.Fatal(err)
	}
	if s.VerifyDovecot("user@example.test", "generated-client-secret") {
		t.Fatal("revoked app password still verifies")
	}
}

func TestAppPasswordLimitAndDisabledMailboxFailClosed(t *testing.T) {
	s := testService()
	actor := authz.Actor{Type: "local_admin", ID: "admin"}
	if _, err := s.CreateOrReplaceUser(context.Background(), actor, Mailbox{Email: "user@example.test", Active: true}, "mail-password"); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < MaxActiveAppPasswords; i++ {
		if _, err := s.CreateAppPassword(context.Background(), actor, "user@example.test", fmt.Sprintf("client-%d", i)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.CreateAppPassword(context.Background(), actor, "user@example.test", "one-too-many"); !errors.Is(err, ErrAppPasswordLimit) {
		t.Fatalf("ninth app password error=%v", err)
	}
	listed := s.ListAppPasswords("user@example.test")
	if len(listed) != MaxActiveAppPasswords {
		t.Fatalf("listed=%d", len(listed))
	}
	secret := "generated-client-secret"
	m := s.Mailboxes["user@example.test"]
	m.Active = false
	s.Mailboxes["user@example.test"] = m
	if s.VerifyDovecot("user@example.test", secret) {
		t.Fatal("disabled mailbox accepted an app password")
	}
}

func TestAppPasswordValidationAndIdempotentRevoke(t *testing.T) {
	s := testService()
	admin := authz.Actor{Type: "local_admin", ID: "admin"}
	if _, err := s.CreateOrReplaceUser(context.Background(), admin, Mailbox{Email: "user@example.test", Active: true}, "mail-password"); err != nil {
		t.Fatal(err)
	}
	for name, label := range map[string]string{"empty": "  ", "too-long": strings.Repeat("x", 129)} {
		t.Run(name, func(t *testing.T) {
			if _, err := s.CreateAppPassword(context.Background(), admin, "user@example.test", label); err == nil {
				t.Fatal("invalid label accepted")
			}
		})
	}
	if _, err := s.CreateAppPassword(context.Background(), admin, "missing@example.test", "phone"); err == nil || !strings.Contains(err.Error(), "mailbox not found") {
		t.Fatalf("missing mailbox error=%v", err)
	}
	s.Secret = func() (string, error) { return "", errors.New("entropy unavailable") }
	if _, err := s.CreateAppPassword(context.Background(), admin, "user@example.test", "phone"); err == nil || !strings.Contains(err.Error(), "entropy unavailable") {
		t.Fatalf("entropy failure=%v", err)
	}
	s.Secret = func() (string, error) { return "short", nil }
	if _, err := s.CreateAppPassword(context.Background(), admin, "user@example.test", "phone"); err == nil || !strings.Contains(err.Error(), "password too short") {
		t.Fatalf("short generated secret failure=%v", err)
	}
	s.Secret = func() (string, error) { return "generated-client-secret", nil }
	created, err := s.CreateAppPassword(context.Background(), admin, "user@example.test", "phone")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.RevokeAppPassword(context.Background(), admin, "user@example.test", "app_missing"); err == nil || !strings.Contains(err.Error(), "app password not found") {
		t.Fatalf("missing revoke error=%v", err)
	}
	if err := s.RevokeAppPassword(context.Background(), admin, "user@example.test", created.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.RevokeAppPassword(context.Background(), admin, "user@example.test", created.ID); err != nil {
		t.Fatalf("idempotent revoke failed: %v", err)
	}
}

func TestBearerTokensAndFailureAuditing(t *testing.T) {
	s := testService()
	if err := s.AddToken("scim", "scim_client", "scim-secret"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AuthenticateBearer("", "scim_client"); err == nil {
		t.Fatal("accepted missing bearer")
	}
	actor, err := s.AuthenticateBearer("Bearer scim-secret", "scim_client")
	if err != nil {
		t.Fatal(err)
	}
	if actor.Type != "scim_client" || actor.ID != "scim" {
		t.Fatalf("actor=%#v", actor)
	}
	_, _ = s.CreateOrReplaceUser(context.Background(), authz.Actor{Type: "oidc_subject", ID: "bad"}, Mailbox{Email: "user@example.test", Active: true}, "longenough")
	w := s.Audit.(*audit.MemoryWriter)
	if len(w.Events) == 0 || w.Events[len(w.Events)-1].Result != "denied" {
		t.Fatalf("missing denied audit %#v", w.Events)
	}
	_, _ = s.CreateAppPassword(context.Background(), authz.Actor{Type: "local_admin", ID: "admin"}, "missing@example.test", "phone")
	if w.Events[len(w.Events)-1].Result != "failure" {
		t.Fatalf("missing failure audit %#v", w.Events)
	}
}

type failingAudit struct{}

func (f failingAudit) Write(context.Context, audit.Event) error { return assertErr("audit down") }

type assertErr string

func (e assertErr) Error() string { return string(e) }

func TestIdentityMutationsFailClosedWhenAuditWriteFails(t *testing.T) {
	s := NewService("example.test")
	s.Audit = failingAudit{}
	s.Authorizer = authz.StaticAuthorizer{}
	actor := authz.Actor{Type: "local_admin", ID: "admin"}
	if _, err := s.CreateOrReplaceUser(context.Background(), actor, Mailbox{Email: "user@example.test", Active: true}, "long-password"); err == nil || !strings.Contains(err.Error(), "audit down") {
		t.Fatalf("expected audit failure, got %v", err)
	}
	if _, ok := s.GetUser("user@example.test"); ok {
		t.Fatal("mailbox mutated despite audit failure")
	}
}

func TestVolatileAppPasswordMutationsFailClosedWhenAuditWriteFails(t *testing.T) {
	s := testService()
	actor := authz.Actor{Type: "local_admin", ID: "admin"}
	if _, err := s.CreateOrReplaceUser(context.Background(), actor, Mailbox{Email: "user@example.test", Active: true}, "mail-password"); err != nil {
		t.Fatal(err)
	}
	s.Audit = failingAudit{}
	if _, err := s.CreateAppPassword(context.Background(), actor, "user@example.test", "phone"); err == nil || !strings.Contains(err.Error(), "audit down") {
		t.Fatalf("create audit failure=%v", err)
	}
	if len(s.ListAppPasswords("user@example.test")) != 0 {
		t.Fatal("app password created despite audit failure")
	}
	s.Audit = &audit.MemoryWriter{}
	created, err := s.CreateAppPassword(context.Background(), actor, "user@example.test", "phone")
	if err != nil {
		t.Fatal(err)
	}
	s.Audit = failingAudit{}
	if err := s.RevokeAppPassword(context.Background(), actor, "user@example.test", created.ID); err == nil || !strings.Contains(err.Error(), "audit down") {
		t.Fatalf("revoke audit failure=%v", err)
	}
	if !s.VerifyDovecot("user@example.test", created.SecretOnce) {
		t.Fatal("app password revoked despite audit failure")
	}
}

func TestConcurrentDovecotReadsAndAppPasswordProjection(t *testing.T) {
	s := testService()
	d := &daemon.Service{}
	s.BindDaemon(d)
	actor := authz.Actor{Type: "local_admin", ID: "admin"}
	if _, err := s.CreateOrReplaceUser(context.Background(), actor, Mailbox{Email: "user@example.test", Active: true}, "mail-password"); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 10; j++ {
				got := d.DovecotPassdb("concurrent", daemon.PassdbRequest{Username: "user@example.test", Secret: "generated-client-secret", Protocol: "imap"})
				if got.Decision != daemon.OK && got.Decision != daemon.Reject {
					t.Errorf("unexpected passdb decision during projection: %#v", got)
				}
			}
		}()
	}
	for i := 0; i < 4; i++ {
		created, err := s.CreateAppPassword(context.Background(), actor, "user@example.test", fmt.Sprintf("concurrent-%d", i))
		if err != nil {
			t.Fatal(err)
		}
		if err := s.RevokeAppPassword(context.Background(), actor, "user@example.test", created.ID); err != nil {
			t.Fatal(err)
		}
	}
	wg.Wait()
}

func TestAPITokenScopeCannotCrossMailbox(t *testing.T) {
	s := testService()
	actor := authz.Actor{Type: "local_admin", ID: "admin"}
	if _, err := s.CreateOrReplaceUser(context.Background(), actor, Mailbox{Email: "user@example.test", Active: true}, "long-password"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateOrReplaceUser(context.Background(), actor, Mailbox{Email: "other@example.test", Active: true}, "long-password"); err != nil {
		t.Fatal(err)
	}
	if err := s.AddTokenWithScopes("user-token", "api_token", "api-secret-token", "mailbox:user@example.test:mailbox:app_password.create"); err != nil {
		t.Fatal(err)
	}
	apiActor, err := s.AuthenticateBearer("Bearer api-secret-token", "api_token")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateAppPassword(context.Background(), apiActor, "user@example.test", "phone"); err != nil {
		t.Fatalf("same mailbox denied: %v", err)
	}
	if _, err := s.CreateAppPassword(context.Background(), apiActor, "other@example.test", "phone"); err == nil {
		t.Fatal("cross-mailbox app-password create allowed")
	}
}
