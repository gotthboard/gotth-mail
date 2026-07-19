package webmail

import (
	"bufio"
	"context"
	"net"
	"os"
	"strings"
	"testing"
	"time"
)

func TestNetSMTPSubmitterTalksSMTPAndRejectsInvalidEnvelope(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	got := make(chan []string, 1)
	go fakeSMTPServer(t, ln, got)
	s := NetSMTPSubmitter{Addr: ln.Addr().String(), HelloName: "gmf.test", Timeout: 5 * time.Second}
	if err := s.Submit(context.Background(), Envelope{From: "sender@example.test", To: []string{"rcpt@example.test"}}, []byte("Subject: ok\r\n\r\nbody")); err != nil {
		t.Fatal(err)
	}
	lines := <-got
	joined := strings.Join(lines, "\n")
	for _, want := range []string{"MAIL FROM:<sender@example.test>", "RCPT TO:<rcpt@example.test>", "Subject: ok", "body"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("smtp transcript missing %q in\n%s", want, joined)
		}
	}
	if !strings.Contains(joined, "EHLO gmf.test") && !strings.Contains(joined, "HELO gmf.test") {
		t.Fatalf("smtp transcript missing HELO/EHLO in\n%s", joined)
	}
	if err := s.Submit(context.Background(), Envelope{From: "bad from", To: []string{"rcpt@example.test"}}, []byte("x")); err == nil {
		t.Fatal("invalid sender accepted")
	}
	if err := s.Submit(context.Background(), Envelope{From: "sender@example.test"}, []byte("x")); err == nil {
		t.Fatal("empty recipient list accepted")
	}
	if err := s.Submit(context.Background(), Envelope{From: "sender@example.test", To: []string{"rcpt@example.test"}}, nil); err == nil {
		t.Fatal("empty message accepted")
	}
}

func TestNetSMTPSubmitterLiveComposePostfix(t *testing.T) {
	addr := os.Getenv("GMF_LIVE_SMTP_ADDR")
	if addr == "" {
		t.Skip("GMF_LIVE_SMTP_ADDR not set")
	}
	subject := os.Getenv("GMF_LIVE_SMTP_SUBJECT")
	if subject == "" {
		subject = "GopherMailForge webmail SMTP smoke"
	}
	msg := []byte("From: smoke@example.test\r\nTo: alias@example.test\r\nSubject: " + subject + "\r\n\r\ncontainerized-webmail-smtp-smoke")
	s := NetSMTPSubmitter{Addr: addr, HelloName: "gophermailforge-webmail-smoke", Timeout: 20 * time.Second}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	if err := s.Submit(ctx, Envelope{From: "smoke@example.test", To: []string{"alias@example.test"}}, msg); err != nil {
		t.Fatal(err)
	}
}

func fakeSMTPServer(t *testing.T, ln net.Listener, got chan<- []string) {
	t.Helper()
	conn, err := ln.Accept()
	if err != nil {
		return
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	r := bufio.NewReader(conn)
	var lines []string
	write := func(s string) { _, _ = conn.Write([]byte(s)) }
	write("220 fake.example.test ESMTP\r\n")
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")
		lines = append(lines, line)
		upper := strings.ToUpper(line)
		switch {
		case strings.HasPrefix(upper, "HELO") || strings.HasPrefix(upper, "EHLO"):
			write("250 fake.example.test\r\n")
		case strings.HasPrefix(upper, "MAIL FROM:"):
			write("250 ok\r\n")
		case strings.HasPrefix(upper, "RCPT TO:"):
			write("250 ok\r\n")
		case upper == "DATA":
			write("354 end with dot\r\n")
			for {
				data, err := r.ReadString('\n')
				if err != nil {
					return
				}
				data = strings.TrimRight(data, "\r\n")
				if data == "." {
					break
				}
				lines = append(lines, data)
			}
			write("250 queued\r\n")
		case upper == "QUIT":
			write("221 bye\r\n")
			got <- lines
			return
		default:
			write("250 ok\r\n")
		}
	}
}
