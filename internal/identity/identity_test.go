package identity

import (
	"context"
	"strings"
	"testing"
	"time"

	"forgejo/linus/gophermailforge/internal/audit"
	"forgejo/linus/gophermailforge/internal/authz"
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
	if len(s.Audit.Events) < 3 {
		t.Fatalf("missing audit events %#v", s.Audit.Events)
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
	if actor.Type != "scim_client" || actor.ID != "scim" || len(actor.Scopes) == 0 {
		t.Fatalf("actor=%#v", actor)
	}
	_, _ = s.CreateOrReplaceUser(context.Background(), authz.Actor{Type: "oidc_subject", ID: "bad"}, Mailbox{Email: "user@example.test", Active: true}, "longenough")
	if len(s.Audit.Events) == 0 || s.Audit.Events[len(s.Audit.Events)-1].Result != "denied" {
		t.Fatalf("missing denied audit %#v", s.Audit.Events)
	}
	_, _ = s.CreateAppPassword(context.Background(), authz.Actor{Type: "local_admin", ID: "admin"}, "missing@example.test", "phone")
	if s.Audit.Events[len(s.Audit.Events)-1].Result != "failure" {
		t.Fatalf("missing failure audit %#v", s.Audit.Events)
	}
}
