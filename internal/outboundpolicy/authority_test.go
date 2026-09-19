package outboundpolicy

import "testing"

func TestAuthenticatedIdentitySeparatesMailboxAndSystemAuthority(t *testing.T) {
	mailbox, system := AuthenticatedIdentity("user@example.test")
	if mailbox != "user@example.test" || system != "" {
		t.Fatalf("mailbox=%q system=%q", mailbox, system)
	}
	mailbox, system = AuthenticatedIdentity("system:alerts@example.test")
	if mailbox != "" || system != "system:alerts@example.test" {
		t.Fatalf("mailbox=%q system=%q", mailbox, system)
	}
	mailbox, system = AuthenticatedIdentity("System:alerts@example.test")
	if mailbox != "System:alerts@example.test" || system != "" {
		t.Fatalf("case-variant authority escalated: mailbox=%q system=%q", mailbox, system)
	}
}
