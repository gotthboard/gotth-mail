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
	commands := make(chan string, 64)
	go fakeIMAPServer(t, ln, commands)
	c := NetIMAPClient{Addr: ln.Addr().String(), Username: "u@example.test", Password: "secret", Timeout: 5 * time.Second}
	folders, err := c.ListFolders(context.Background(), "u@example.test")
	if err != nil || len(folders) != 1 || folders[0] != "INBOX" {
		t.Fatalf("folders=%#v err=%v", folders, err)
	}
	detailed, err := c.ListFoldersDetailed(context.Background(), "u@example.test")
	if err != nil || len(detailed) != 1 || detailed[0].Name != "INBOX" || detailed[0].Unread != 3 {
		t.Fatalf("folder details=%#v err=%v", detailed, err)
	}
	msgs, err := c.ListMessages(context.Background(), "u@example.test", "INBOX", "", 10)
	if err != nil || len(msgs) != 2 || msgs[0].ID != "2" || msgs[1].ID != "1" || msgs[0].Subject != "Fake IMAP smoke" || msgs[0].BodyText != "" || !msgs[0].HasAttachments || !containsString(msgs[0].Flags, `\Seen`) {
		t.Fatalf("msgs=%#v err=%v", msgs, err)
	}
	search, err := c.Search(context.Background(), "u@example.test", "INBOX", "fake-body", "", 10)
	if err != nil || len(search) != 2 || search[0].ID != "2" || search[1].ID != "1" {
		t.Fatalf("search=%#v err=%v", search, err)
	}
	msg, err := c.ReadMessage(context.Background(), "u@example.test", "INBOX", "1")
	if err != nil || msg.From != "sender@example.test" {
		t.Fatalf("read=%#v err=%v", msg, err)
	}
	used, limit, err := c.Quota(context.Background(), "u@example.test")
	if err != nil || used != 12*1024 || limit != 1024*1024 {
		t.Fatalf("quota=%d/%d err=%v", used, limit, err)
	}
	if err := c.SetFlag(context.Background(), "u@example.test", "INBOX", "1", "seen", true); err != nil {
		t.Fatal(err)
	}
	if err := c.Move(context.Background(), "u@example.test", "INBOX", "1", "Archive"); err != nil {
		t.Fatal(err)
	}
	if err := c.Delete(context.Background(), "u@example.test", "INBOX", "1"); err != nil {
		t.Fatal(err)
	}
	close(commands)
	var transcript string
	for command := range commands {
		transcript += command + "\n"
	}
	for _, want := range []string{"STATUS \"INBOX\" (UNSEEN)", "UID SEARCH ALL", "BODY.PEEK[HEADER.FIELDS", "UID FETCH 1 (FLAGS BODY[])", `UID STORE 1 +FLAGS.SILENT (\Seen)`, `UID MOVE 1 "Archive"`, `UID EXPUNGE 1`} {
		if !strings.Contains(transcript, want) {
			t.Fatalf("missing %q from IMAP transcript:\n%s", want, transcript)
		}
	}
	if got := strings.Count(transcript, " SELECT "); got != 6 {
		t.Fatalf("unexpected SELECT count %d; list summaries must reuse the selected mailbox:\n%s", got, transcript)
	}
	if err := c.Delete(context.Background(), "u@example.test", "INBOX", "1 EXPUNGE"); err == nil {
		t.Fatal("unsafe IMAP UID accepted")
	}
	if _, err := c.Search(context.Background(), "u@example.test", "INBOX", strings.Repeat("x", 201), "", 10); err == nil {
		t.Fatal("oversized IMAP search accepted")
	}
	if _, err := c.ListMessages(context.Background(), "u@example.test", "INBOX\r\nEXPUNGE", "", 10); err == nil {
		t.Fatal("unsafe IMAP mailbox accepted")
	}
	if err := c.Move(context.Background(), "u@example.test", "INBOX", "1", "Archive\r\nEXPUNGE"); err == nil {
		t.Fatal("unsafe IMAP destination accepted")
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

func fakeIMAPServer(t *testing.T, ln net.Listener, commands chan<- string) {
	t.Helper()
	for i := 0; i < 9; i++ {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		go handleFakeIMAP(conn, commands)
	}
}

func handleFakeIMAP(conn net.Conn, commands chan<- string) {
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
		commands <- line
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
		case "STATUS":
			write("* STATUS INBOX (UNSEEN 3)\r\n" + tag + " OK status done\r\n")
		case "UID":
			if len(fields) < 3 {
				write(tag + " BAD missing UID command\r\n")
				continue
			}
			switch strings.ToUpper(fields[2]) {
			case "SEARCH":
				write("* SEARCH 1 2\r\n" + tag + " OK search done\r\n")
			case "FETCH":
				payload := msg
				if strings.Contains(line, "BODY.PEEK") {
					payload = "From: sender@example.test\r\nTo: u@example.test\r\nDate: Thu, 01 Jan 1970 00:00:01 +0000\r\nSubject: Fake IMAP smoke\r\nContent-Type: multipart/mixed; boundary=fake\r\n\r\n"
				}
				write("* 1 FETCH (UID 1 FLAGS (\\Seen) BODY[] {" + strconv.Itoa(len(payload)) + "}\r\n" + payload + ")\r\n" + tag + " OK fetch done\r\n")
			case "STORE", "MOVE", "EXPUNGE":
				write(tag + " OK uid mutation done\r\n")
			default:
				write(tag + " BAD unknown UID command\r\n")
			}
		case "GETQUOTAROOT":
			write("* QUOTAROOT INBOX \"\"\r\n* QUOTA \"\" (STORAGE 12 1024)\r\n" + tag + " OK quota done\r\n")
		case "LOGOUT":
			write("* BYE\r\n" + tag + " OK logout\r\n")
			return
		default:
			write(tag + " BAD unknown\r\n")
		}
	}
}
