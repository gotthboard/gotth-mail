package daemon

import "testing"

func fixture() Service {
	verifier := MakeDjangoPBKDF2SHA256("app-secret", "testsalt", 1200)
	return Service{
		Domains: map[string]Domain{
			"example.test":  {Name: "example.test", Enabled: true, Transport: "virtual:", DKIMSelector: "mail", DKIMPrivateKeyPath: "/run/gotth-mail/dkim/example.test.private"},
			"disabled.test": {Name: "disabled.test", Enabled: false},
		},
		Mailboxes: map[string]Mailbox{
			"user@example.test":     {Address: "user@example.test", Enabled: true, Home: "/mail/example.test/user", UID: 5000, GID: 5000, QuotaBytes: 1073741824, Verifier: verifier},
			"disabled@example.test": {Address: "disabled@example.test", Enabled: false, Verifier: verifier},
		},
		Aliases:    map[string]Alias{"alias@example.test": {Address: "alias@example.test", Enabled: true, Targets: []string{"user@example.test"}}},
		RateLimits: map[string]RateLimit{"flood@example.test": {Allowed: false, RetryAfterSec: 60}},
	}
}

func TestPostfixContractsHappyAndFailurePaths(t *testing.T) {
	s := fixture()
	for name, got := range map[string]Response{
		"domain":       s.PostfixDomain("c", "example.test"),
		"recipient":    s.PostfixRecipient("c", "user@example.test"),
		"mailbox":      s.PostfixMailbox("c", "user@example.test"),
		"alias":        s.PostfixAlias("c", "alias@example.test"),
		"sender-login": s.PostfixSenderLogin("c", SenderLoginRequest{SASLUsername: "user@example.test", MailFrom: "user@example.test", ClientIP: "192.0.2.10"}),
		"transport":    s.PostfixTransport("c", "example.test"),
	} {
		if got.Decision != OK {
			t.Fatalf("%s decision=%s reason=%s", name, got.Decision, got.Reason)
		}
	}
	if got := s.PostfixDomain("c", "disabled.test"); got.Decision != Reject || got.Reason != "domain_disabled" {
		t.Fatalf("disabled domain got %#v", got)
	}
	if got := s.PostfixRecipient("c", "missing@example.test"); got.Decision != NotFound {
		t.Fatalf("missing recipient got %#v", got)
	}
	if got := s.PostfixSenderLogin("c", SenderLoginRequest{SASLUsername: "user@example.test", MailFrom: "other@example.test"}); got.Decision != Reject {
		t.Fatalf("sender mismatch got %#v", got)
	}
	if got := s.PostfixRateLimit("c", "flood@example.test"); got.Decision != Reject || got.RetryAfterSec != 60 {
		t.Fatalf("rate limit got %#v", got)
	}
	if got := (Service{Unavailable: true}).PostfixRecipient("c", "user@example.test"); got.Decision != Defer {
		t.Fatalf("db unavailable got %#v", got)
	}
}

func TestDovecotContractsVerifyDjangoHashAndRejectOIDC(t *testing.T) {
	s := fixture()
	if got := s.DovecotPassdb("c", PassdbRequest{Username: "user@example.test", Secret: "app-secret", Protocol: "imap"}); got.Decision != OK {
		t.Fatalf("passdb ok got %#v", got)
	}
	if got := s.DovecotPassdb("c", PassdbRequest{Username: "user@example.test", Secret: "wrong", Protocol: "imap"}); got.Decision != Reject || got.Reason != "invalid_secret" {
		t.Fatalf("wrong secret got %#v", got)
	}
	if got := s.DovecotPassdb("c", PassdbRequest{Username: "user@example.test", Secret: "oidc:token", Protocol: "imap"}); got.Decision != Reject || got.Reason != "oidc_token_not_mail_secret" {
		t.Fatalf("oidc secret got %#v", got)
	}
	if got := s.DovecotUserdb("c", "user@example.test"); got.Decision != OK || got.Home == "" || got.UID == 0 || got.QuotaBytes == 0 {
		t.Fatalf("userdb got %#v", got)
	}
	if got := s.DovecotQuota("c", QuotaRequest{Address: "user@example.test", QuotaBytes: 2048}); got.Decision != OK || got.QuotaBytes != 2048 {
		t.Fatalf("quota got %#v", got)
	}
	if got := s.DovecotPassdb("c", PassdbRequest{Username: "disabled@example.test", Secret: "app-secret", Protocol: "imap"}); got.Decision != Reject || got.Reason != "mailbox_disabled" {
		t.Fatalf("disabled got %#v", got)
	}
}

func TestRspamdContracts(t *testing.T) {
	s := fixture()
	if got := s.RspamdLocalDomains("c"); got.Decision != OK || len(got.Domains) != 1 || got.Domains[0] != "example.test" {
		t.Fatalf("local domains got %#v", got)
	}
	if got := s.RspamdDKIM("c", "example.test"); got.Decision != OK || got.Selector != "mail" || got.KeyPath == "" {
		t.Fatalf("dkim got %#v", got)
	}
	if got := s.RspamdDKIM("c", "missing.test"); got.Decision != NotFound {
		t.Fatalf("missing dkim got %#v", got)
	}
	if got := s.RspamdSigningDecision("c", "example.test"); got.Decision != OK || got.Reason != "signing_allowed" {
		t.Fatalf("signing got %#v", got)
	}
}

func TestVerifierRejectsUnsupportedHash(t *testing.T) {
	if err := VerifyDjangoPBKDF2SHA256("plaintext", "secret"); err == nil {
		t.Fatal("unsupported verifier accepted")
	}
}
