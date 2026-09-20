package main

import (
	"bufio"
	"fmt"
	"net"
	"strings"
	"testing"

	"forgejo/gotthboard/gotth-mail/internal/daemon"
)

func TestPostfixTCPMaps(t *testing.T) {
	service := daemon.Service{
		Domains:   map[string]daemon.Domain{"example.test": {Name: "example.test", Enabled: true}},
		Mailboxes: map[string]daemon.Mailbox{"user@example.test": {Address: "user@example.test", Enabled: true}},
		Aliases:   map[string]daemon.Alias{"alias@example.test": {Address: "alias@example.test", Enabled: true, Targets: []string{"user@example.test"}}},
	}
	for _, test := range []struct {
		kind postfixMapKind
		key  string
		want string
	}{
		{postfixDomainMap, "example.test", "200 1"},
		{postfixDomainMap, "missing.test", "500 not found"},
		{postfixMailboxMap, "user@example.test", "200 1"},
		{postfixAliasMap, "alias@example.test", "200 user@example.test"},
	} {
		if got := postfixMapExchange(t, test.kind, service, "get "+test.key+"\n"); got != test.want {
			t.Fatalf("kind=%d key=%q got=%q want=%q", test.kind, test.key, got, test.want)
		}
	}
}

func TestPostfixTCPMapBoundsAndUnavailable(t *testing.T) {
	if got := postfixMapExchange(t, postfixDomainMap, daemon.Service{Unavailable: true}, "get example.test\n"); got != "400 temporary lookup failure" {
		t.Fatalf("unavailable=%q", got)
	}
	if got := postfixMapExchange(t, postfixDomainMap, daemon.Service{}, "put example.test\n"); got != "400 malformed request" {
		t.Fatalf("malformed=%q", got)
	}
	if got := postfixMapExchange(t, postfixDomainMap, daemon.Service{}, "get "+strings.Repeat("x", 5000)+"\n"); got != "" {
		t.Fatalf("oversized=%q", got)
	}
}

func postfixMapExchange(t *testing.T, kind postfixMapKind, service daemon.Service, request string) string {
	t.Helper()
	server, client := net.Pipe()
	done := make(chan struct{})
	go func() {
		handlePostfixMap(server, kind, service)
		close(done)
	}()
	_, _ = fmt.Fprint(client, request)
	line, _ := bufio.NewReader(client).ReadString('\n')
	_ = client.Close()
	<-done
	return strings.TrimSpace(line)
}
