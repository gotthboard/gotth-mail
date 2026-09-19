package main

import (
	"os"
	"strings"
	"testing"
)

func TestHelperTokenRequiresOneBoundedSource(t *testing.T) {
	t.Setenv("GOTTH_MAIL_POSTFIX_HELPER_TOKEN", "0123456789abcdef0123456789abcdef")
	token, err := helperToken()
	if err != nil || token == "" {
		t.Fatalf("token=%q err=%v", token, err)
	}
	path := t.TempDir() + "/token"
	if err := os.WriteFile(path, []byte("abcdef0123456789abcdef0123456789\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GOTTH_MAIL_POSTFIX_HELPER_TOKEN_FILE", path)
	if _, err := helperToken(); err == nil {
		t.Fatal("accepted two helper token sources")
	}
	t.Setenv("GOTTH_MAIL_POSTFIX_HELPER_TOKEN", "")
	token, err = helperToken()
	if err != nil || token != "abcdef0123456789abcdef0123456789" {
		t.Fatalf("file token=%q err=%v", token, err)
	}
}

func TestReleaseTokenUsesIndependentConfiguration(t *testing.T) {
	t.Setenv("GOTTH_MAIL_POSTFIX_RELEASE_TOKEN", "abcdef0123456789abcdef0123456789")
	token, err := releaseToken()
	if err != nil || token != "abcdef0123456789abcdef0123456789" {
		t.Fatalf("token=%q err=%v", token, err)
	}
}

func TestRunDeliveryRejectsMalformedArgumentsBeforeIO(t *testing.T) {
	t.Setenv("GOTTH_MAIL_POSTFIX_HELPER_TOKEN", "0123456789abcdef0123456789abcdef")
	if err := runDelivery([]string{"--queue-id", "bad", "--recipient", "one@example.net"}, strings.NewReader("message")); err == nil {
		t.Fatal("accepted missing original recipient")
	}
}

func TestDeliveryAuthoritySeparatesMailboxAndSystemSASLIdentities(t *testing.T) {
	mailbox, system, err := deliveryAuthority("user@example.test", "", "192.0.2.1")
	if err != nil || mailbox != "user@example.test" || system != "" {
		t.Fatalf("mailbox=%q system=%q err=%v", mailbox, system, err)
	}
	mailbox, system, err = deliveryAuthority("system:alerts@example.test", "", "192.0.2.1")
	if err != nil || mailbox != "" || system != "system:alerts@example.test" {
		t.Fatalf("mailbox=%q system=%q err=%v", mailbox, system, err)
	}
	if _, _, err := deliveryAuthority("user@example.test", "system:alerts@example.test", ""); err == nil {
		t.Fatal("accepted ambiguous mailbox and system authority")
	}
}

func TestDeliveryAuthorityDoesNotMislabelInboundNullSender(t *testing.T) {
	mailbox, system, err := deliveryAuthority("", "system:mailer-daemon@example.test", "192.0.2.1")
	if err != nil || mailbox != "" || system != "" {
		t.Fatalf("mailbox=%q system=%q err=%v", mailbox, system, err)
	}
	mailbox, system, err = deliveryAuthority("", "system:mailer-daemon@example.test", "")
	if err != nil || mailbox != "" || system != "system:mailer-daemon@example.test" {
		t.Fatalf("mailbox=%q system=%q err=%v", mailbox, system, err)
	}
}
