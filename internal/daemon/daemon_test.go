package daemon

import (
	"strings"
	"testing"

	"forgejo/gotthboard/gotth-mail/internal/audit"
)

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

func TestDjangoPBKDF2ByteAndStringInputsMatch(t *testing.T) {
	const secret = "sëcret phrase"
	want := MakeDjangoPBKDF2SHA256(secret, "fixed-salt", 1200)
	got := MakeDjangoPBKDF2SHA256Bytes([]byte(secret), "fixed-salt", 1200)
	if got != want {
		t.Fatalf("byte-input verifier mismatch: got %q want %q", got, want)
	}
	if err := VerifyDjangoPBKDF2SHA256(got, secret); err != nil {
		t.Fatalf("byte-input verifier rejected: %v", err)
	}
}

func TestDovecotPassdbAuditsAppPasswordUse(t *testing.T) {
	w := &audit.MemoryWriter{}
	s := Service{Audit: w, Mailboxes: map[string]Mailbox{"user@example.test": {Address: "user@example.test", Enabled: true, Verifier: MakeDjangoPBKDF2SHA256("mail-secret", "salt", 1200)}}, AppPasswordVerifiers: map[string][]string{"user@example.test": {MakeDjangoPBKDF2SHA256("app-secret", "salt2", 1200)}}}
	if got := s.DovecotPassdb("c", PassdbRequest{Username: "user@example.test", Secret: "app-secret", Protocol: "imap"}); got.Decision != OK {
		t.Fatalf("got %#v", got)
	}
	if len(w.Events) != 1 || w.Events[0].Action != "app_password.use" || w.Events[0].Result != "success" {
		t.Fatalf("events %#v", w.Events)
	}
	if got := s.DovecotPassdb("c", PassdbRequest{Username: "user@example.test", Secret: "wrong", Protocol: "imap"}); got.Decision != Reject {
		t.Fatalf("got %#v", got)
	}
	if len(w.Events) != 2 || w.Events[1].Result != "failure" || w.Events[1].ErrorCode != "invalid_secret" {
		t.Fatalf("events %#v", w.Events)
	}
}

func TestDjangoVerifierContractIsPBKDF2SHA256Only(t *testing.T) {
	valid := MakeDjangoPBKDF2SHA256("secret", "salt", 1200)
	if err := ValidateDjangoPBKDF2SHA256(valid); err != nil {
		t.Fatalf("valid pbkdf2 verifier rejected: %v", err)
	}
	cases := []string{
		"argon2$argon2id$v=19$m=102400,t=2,p=8$c2FsdA$ZGlnZXN0",
		"bcrypt_sha256$$2b$12$abcdefghijklmnopqrstuu5sNrZfPq",
		"pbkdf2_sha1$1200$salt$ZmFrZQ==",
		"pbkdf2_sha256$1200$$" + valid[strings.LastIndex(valid, "$")+1:],
		"pbkdf2_sha256$1200$salt$ZmFrZQ==",
	}
	for _, tc := range cases {
		if err := ValidateDjangoPBKDF2SHA256(tc); err == nil {
			t.Fatalf("accepted unsupported/invalid verifier %q", tc)
		}
	}
}
