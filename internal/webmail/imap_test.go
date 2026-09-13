package webmail

import (
	"bufio"
	"context"
	"net"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestNetIMAPClientFoldersListSearchReadWithFakeServer(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go fakeIMAPServer(t, ln)
	c := NetIMAPClient{Addr: ln.Addr().String(), Username: "u@example.test", Password: "secret", Timeout: 5 * time.Second}
	folders, err := c.ListFolders(context.Background(), "u@example.test")
	if err != nil || len(folders) != 1 || folders[0] != "INBOX" {
		t.Fatalf("folders=%#v err=%v", folders, err)
	}
	msgs, err := c.ListMessages(context.Background(), "u@example.test", "INBOX", "", 10)
	if err != nil || len(msgs) != 1 || msgs[0].Subject != "Fake IMAP smoke" || !strings.Contains(msgs[0].BodyText, "fake-body") {
		t.Fatalf("msgs=%#v err=%v", msgs, err)
	}
	search, err := c.Search(context.Background(), "u@example.test", "INBOX", "fake-body", "", 10)
	if err != nil || len(search) != 1 {
		t.Fatalf("search=%#v err=%v", search, err)
	}
	msg, err := c.ReadMessage(context.Background(), "u@example.test", "INBOX", "1")
	if err != nil || msg.From != "sender@example.test" {
		t.Fatalf("read=%#v err=%v", msg, err)
	}
}

func TestIMAPMailboxNameParsesQuotedAndAtomNames(t *testing.T) {
	if got := imapMailboxName(`* LIST (\\HasNoChildren) "." INBOX`); got != "INBOX" {
		t.Fatalf("atom mailbox=%q", got)
	}
	if got := imapMailboxName(`* LIST (\\HasNoChildren) "/" "Sent Items"`); got != "Sent Items" {
		t.Fatalf("quoted mailbox=%q", got)
	}
}

func TestNetIMAPClientLiveComposeDovecot(t *testing.T) {
	addr := os.Getenv("GOTTH_MAIL_LIVE_IMAP_ADDR")
	if addr == "" {
		t.Skip("GOTTH_MAIL_LIVE_IMAP_ADDR not set")
	}
	password := os.Getenv("GOTTH_MAIL_LIVE_IMAP_PASSWORD")
	if password == "" {
		t.Fatal("GOTTH_MAIL_LIVE_IMAP_PASSWORD required")
	}
	user := os.Getenv("GOTTH_MAIL_LIVE_IMAP_USER")
	if user == "" {
		user = "smoke@example.test"
	}
	expected := os.Getenv("GOTTH_MAIL_LIVE_IMAP_SUBJECT")
	c := NetIMAPClient{Addr: addr, Username: user, Password: password, Timeout: 20 * time.Second}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	folders, err := c.ListFolders(ctx, user)
	if err != nil {
		t.Fatal(err)
	}
	if !containsString(folders, "INBOX") {
		t.Fatalf("INBOX missing from folders %#v", folders)
	}
	msgs, err := c.ListMessages(ctx, user, "INBOX", "", 20)
	if err != nil {
		t.Fatal(err)
	}
	if len(msgs) == 0 {
		t.Fatal("no live IMAP messages returned")
	}
	if expected != "" {
		found := false
		for _, msg := range msgs {
			if strings.Contains(msg.Subject, expected) || strings.Contains(msg.BodyText, expected) || strings.Contains(msg.BodyText, "containerized-webmail-imap-smoke") {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("expected subject/body marker %q not found in %#v", expected, msgs)
		}
	}
}

func containsString(values []string, want string) bool {
	for _, v := range values {
		if v == want {
			return true
		}
	}
	return false
}

func fakeIMAPServer(t *testing.T, ln net.Listener) {
	t.Helper()
	for i := 0; i < 4; i++ {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		go handleFakeIMAP(conn)
	}
}

func handleFakeIMAP(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	r := bufio.NewReader(conn)
	write := func(s string) { _, _ = conn.Write([]byte(s)) }
	write("* OK fake imap ready\r\n")
	msg := "From: sender@example.test\r\nTo: u@example.test\r\nDate: Thu, 01 Jan 1970 00:00:01 +0000\r\nSubject: Fake IMAP smoke\r\n\r\nfake-body\r\n"
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		tag, cmd := fields[0], strings.ToUpper(fields[1])
		switch cmd {
		case "LOGIN":
			write(tag + " OK logged in\r\n")
		case "LIST":
			write("* LIST (\\HasNoChildren) \"/\" \"INBOX\"\r\n" + tag + " OK list done\r\n")
		case "SELECT":
			write("* 1 EXISTS\r\n" + tag + " OK select done\r\n")
		case "SEARCH":
			write("* SEARCH 1\r\n" + tag + " OK search done\r\n")
		case "FETCH":
			write("* 1 FETCH (BODY[] {" + strconv.Itoa(len(msg)) + "}\r\n" + msg + ")\r\n" + tag + " OK fetch done\r\n")
		case "LOGOUT":
			write("* BYE\r\n" + tag + " OK logout\r\n")
			return
		default:
			write(tag + " BAD unknown\r\n")
		}
	}
}
