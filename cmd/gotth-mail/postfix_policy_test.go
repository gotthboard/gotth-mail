package main

import (
	"bufio"
	"fmt"
	"net"
	"strings"
	"testing"

	"forgejo/gotthboard/gotth-mail/internal/daemon"
	"forgejo/gotthboard/gotth-mail/internal/outboundpolicy"
	"forgejo/gotthboard/gotth-mail/internal/store"
	"forgejo/gotthboard/gotth-mail/internal/testpg"
)

func TestPostfixPolicyAuthenticatedSubmissionUsesWiredDatabasePolicy(t *testing.T) {
	db := testpg.DB(t, store.MigrateSQL)
	if _, err := db.Exec(`INSERT INTO domains(id,name,enabled,outbound_scope,outbound_policy_revision,created_at,updated_at) VALUES ('00000000-0000-4000-8000-000000000a01','example.test',true,'same_domain_only',2,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO mailboxes(id,domain_id,local_part,enabled,created_at,updated_at) VALUES ('00000000-0000-4000-8000-000000000a02','00000000-0000-4000-8000-000000000a01','user',true,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)`); err != nil {
		t.Fatal(err)
	}
	svc := daemon.Service{OutboundPolicy: &outboundpolicy.EnforcementService{DB: db, Queue: outboundpolicy.QueueStore{DB: db}}}
	got := postfixPolicyExchange(t, svc, "request=smtpd_access_policy\nprotocol_state=RCPT\ninstance=session-1\nsasl_username=user@example.test\nsender=user@example.test\nrecipient=outside@example.net\n\n")
	if got != "action=550 5.7.1 outbound recipient forbidden" {
		t.Fatalf("response=%q", got)
	}
	got = postfixPolicyExchange(t, svc, "request=smtpd_access_policy\nprotocol_state=RCPT\ninstance=session-1\nsasl_username=user@example.test\nsender=user@example.test\nrecipient=peer@example.test\n\n")
	if got != "action=DUNNO" {
		t.Fatalf("response=%q", got)
	}
}

func TestPostfixPolicyLeavesExternalRelayDecisionToPostfix(t *testing.T) {
	svc := referenceServer().Daemon
	got := postfixPolicyExchange(t, svc, "request=smtpd_access_policy\nprotocol_state=RCPT\ninstance=session-2\nsender=outside@example.net\nrecipient=elsewhere@example.net\n\n")
	if got != "action=DUNNO" {
		t.Fatalf("response=%q", got)
	}
	got = postfixPolicyExchange(t, svc, "request=smtpd_access_policy\nprotocol_state=RCPT\ninstance=session-2\nsender=outside@example.net\nrecipient=missing@example.test\n\n")
	if got != "action=550 5.1.1 recipient unknown" {
		t.Fatalf("response=%q", got)
	}
}

func TestPostfixPolicyFailsClosedForMalformedAndUnavailableRequests(t *testing.T) {
	got := postfixPolicyExchange(t, daemon.Service{}, "request=smtpd_access_policy\nprotocol_state=DATA\nrecipient=user@example.test\n\n")
	if got != "action=451 4.3.0 unsupported outbound policy request" {
		t.Fatalf("response=%q", got)
	}
	got = postfixPolicyExchange(t, daemon.Service{}, "request=smtpd_access_policy\nprotocol_state=RCPT\nsasl_username=user@example.test\nsender=user@example.test\nrecipient=outside@example.net\n\n")
	if got != "action=451 4.3.0 outbound policy unavailable" {
		t.Fatalf("response=%q", got)
	}
}

func TestPostfixPolicyBoundsInput(t *testing.T) {
	request := "request=smtpd_access_policy\nprotocol_state=RCPT\n" + strings.Repeat("x", 65<<10) + "\n\n"
	got := postfixPolicyExchange(t, daemon.Service{}, request)
	if got != "action=451 4.3.0 outbound policy request unreadable" {
		t.Fatalf("response=%q", got)
	}
}

func postfixPolicyExchange(t *testing.T, svc daemon.Service, request string) string {
	t.Helper()
	server, client := net.Pipe()
	done := make(chan struct{})
	go func() {
		handlePostfixPolicy(server, svc)
		close(done)
	}()
	writeDone := make(chan struct{})
	go func() {
		_, _ = fmt.Fprint(client, request)
		close(writeDone)
	}()
	line, err := bufio.NewReader(client).ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	_ = client.Close()
	<-writeDone
	<-done
	return strings.TrimSpace(line)
}
