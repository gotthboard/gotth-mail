package webmail

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"errors"
	"math/big"
	"net"
	"net/smtp"
	"net/textproto"
	"os"
	"strings"
	"testing"
	"time"
)

func TestSMTPFailureClassificationPreservesAcceptanceBoundary(t *testing.T) {
	for _, tc := range []struct {
		name      string
		err       error
		ambiguous bool
		want      SMTPFailureClass
	}{
		{"five hundred", &textproto.Error{Code: 550, Msg: "rejected"}, false, SMTPFailurePermanent},
		{"four hundred", &textproto.Error{Code: 451, Msg: "retry"}, false, SMTPFailureRetryable},
		{"transport before acceptance", errors.New("eof"), false, SMTPFailureRetryable},
		{"transport at acceptance", errors.New("eof"), true, SMTPFailureAmbiguous},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var got *SMTPDeliveryError
			if !errors.As(classifySMTPFailure("test", tc.err, tc.ambiguous), &got) || got.Class != tc.want {
				t.Fatalf("got %#v want %s", got, tc.want)
			}
		})
	}
}

func TestNetSMTPSubmitterDoesNotRetryAcceptedMailWhenQUITFails(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go fakeSMTPAcceptThenClose(t, ln)
	s := NetSMTPSubmitter{Addr: ln.Addr().String(), Timeout: 5 * time.Second}
	if err := s.Submit(context.Background(), Envelope{From: "sender@example.test", To: []string{"rcpt@example.test"}}, []byte("Subject: accepted\r\n\r\nbody")); err != nil {
		t.Fatalf("accepted DATA was turned into a retry: %v", err)
	}
}

func TestNetSMTPSubmitterTalksSMTPAndRejectsInvalidEnvelope(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	got := make(chan []string, 1)
	go fakeSMTPServer(t, ln, got)
	s := NetSMTPSubmitter{Addr: ln.Addr().String(), HelloName: "gotth-mail.test", Timeout: 5 * time.Second}
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
	if !strings.Contains(joined, "EHLO gotth-mail.test") && !strings.Contains(joined, "HELO gotth-mail.test") {
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

func TestNetSMTPSubmitterAuthenticatesBeforeEnvelope(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	got := make(chan []string, 1)
	go fakeSMTPAuthServer(t, ln, got)
	s := NetSMTPSubmitter{
		Addr: ln.Addr().String(), HelloName: "gotth-mail-notification", Timeout: 5 * time.Second,
		Auth: smtp.CRAMMD5Auth("system:alerts@example.test", "smtp-secret"),
	}
	if err := s.Submit(context.Background(), Envelope{From: "alerts@example.test", To: []string{"outside@example.net"}}, []byte("Subject: authenticated\r\n\r\nbody")); err != nil {
		t.Fatal(err)
	}
	lines := <-got
	if len(lines) < 3 || lines[1] != "AUTH CRAM-MD5" {
		t.Fatalf("SMTP authentication did not precede the envelope: %#v", lines)
	}
	decoded, err := base64.StdEncoding.DecodeString(lines[2])
	if err != nil || !strings.HasPrefix(string(decoded), "system:alerts@example.test ") {
		t.Fatalf("CRAM-MD5 response identity = %q err=%v", decoded, err)
	}
	for i, line := range lines {
		if strings.HasPrefix(line, "MAIL FROM:") && i < 3 {
			t.Fatalf("envelope began before authentication completed: %#v", lines)
		}
	}
}

func TestNetSMTPSubmitterStartsTLSBeforePlainAuthentication(t *testing.T) {
	certificate, roots := smtpTestCertificate(t, "mail.example.test")
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	got := make(chan []string, 1)
	go fakeSMTPStartTLSServer(t, ln, certificate, got)
	s := NetSMTPSubmitter{
		Addr: ln.Addr().String(), HelloName: "gotth-mail-webmail", Timeout: 5 * time.Second,
		Auth: smtp.PlainAuth("", "user@example.test", "smtp-secret", "mail.example.test"),
		StartTLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS12, ServerName: "mail.example.test", RootCAs: roots,
		},
	}
	if err := s.Submit(context.Background(), Envelope{From: "user@example.test", To: []string{"rcpt@example.test"}}, []byte("Subject: encrypted\r\n\r\nbody")); err != nil {
		t.Fatal(err)
	}
	lines := <-got
	joined := strings.Join(lines, "\n")
	startTLS, auth, mail := strings.Index(joined, "STARTTLS"), strings.Index(joined, "AUTH PLAIN"), strings.Index(joined, "MAIL FROM:")
	if startTLS < 0 || auth <= startTLS || mail <= auth {
		t.Fatalf("SMTP command order = %#v", lines)
	}
}

func TestNetSMTPSubmitterRefusesAuthenticationWhenSTARTTLSIsMissing(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	commands := make(chan []string, 1)
	go func() {
		conn, acceptErr := ln.Accept()
		if acceptErr != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		_, _ = conn.Write([]byte("220 fake.example.test ESMTP\r\n"))
		reader := bufio.NewReader(conn)
		var seen []string
		for {
			line, readErr := reader.ReadString('\n')
			if readErr != nil {
				commands <- seen
				return
			}
			line = strings.TrimRight(line, "\r\n")
			seen = append(seen, line)
			if strings.HasPrefix(strings.ToUpper(line), "EHLO ") {
				_, _ = conn.Write([]byte("250-fake.example.test\r\n250 AUTH PLAIN\r\n"))
			} else {
				_, _ = conn.Write([]byte("500 unexpected\r\n"))
			}
		}
	}()
	s := NetSMTPSubmitter{
		Addr: ln.Addr().String(), HelloName: "gotth-mail-webmail", Timeout: 5 * time.Second,
		Auth:           smtp.PlainAuth("", "user@example.test", "smtp-secret", "mail.example.test"),
		StartTLSConfig: &tls.Config{MinVersion: tls.VersionTLS12, ServerName: "mail.example.test"},
	}
	err = s.Submit(context.Background(), Envelope{From: "user@example.test", To: []string{"rcpt@example.test"}}, []byte("Subject: blocked\r\n\r\nbody"))
	var deliveryErr *SMTPDeliveryError
	if !errors.As(err, &deliveryErr) || deliveryErr.Class != SMTPFailurePermanent || deliveryErr.Phase != "starttls" {
		t.Fatalf("missing STARTTLS error = %#v", err)
	}
	seen := <-commands
	for _, command := range seen {
		if strings.HasPrefix(strings.ToUpper(command), "AUTH ") {
			t.Fatalf("authentication leaked before STARTTLS: %#v", seen)
		}
	}
}

func TestNetSMTPSubmitterLiveComposePostfix(t *testing.T) {
	addr := os.Getenv("GOTTH_MAIL_LIVE_SMTP_ADDR")
	if addr == "" {
		t.Skip("GOTTH_MAIL_LIVE_SMTP_ADDR not set")
	}
	subject := os.Getenv("GOTTH_MAIL_LIVE_SMTP_SUBJECT")
	if subject == "" {
		subject = "GOTTH Mail webmail SMTP smoke"
	}
	from := os.Getenv("GOTTH_MAIL_LIVE_SMTP_FROM")
	if from == "" {
		from = "smoke@example.test"
	}
	to := os.Getenv("GOTTH_MAIL_LIVE_SMTP_TO")
	if to == "" {
		to = "alias@example.test"
	}
	msg := []byte("From: " + from + "\r\nTo: " + to + "\r\nSubject: " + subject + "\r\n\r\ncontainerized-webmail-smtp-smoke")
	s := NetSMTPSubmitter{Addr: addr, HelloName: "gotth-mail-webmail-smoke", Timeout: 20 * time.Second}
	authUser, authPassword := os.Getenv("GOTTH_MAIL_LIVE_SMTP_USERNAME"), os.Getenv("GOTTH_MAIL_LIVE_SMTP_PASSWORD")
	if (authUser == "") != (authPassword == "") {
		t.Fatal("live SMTP username and password must be configured together")
	}
	if authUser != "" {
		s.Auth = smtp.CRAMMD5Auth(authUser, authPassword)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	if err := s.Submit(ctx, Envelope{From: from, To: []string{to}}, msg); err != nil {
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

func fakeSMTPAuthServer(t *testing.T, ln net.Listener, got chan<- []string) {
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
	inData := false
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")
		lines = append(lines, line)
		upper := strings.ToUpper(line)
		switch {
		case inData && line == ".":
			inData = false
			write("250 queued\r\n")
		case inData:
		case strings.HasPrefix(upper, "EHLO"):
			write("250-fake.example.test\r\n250 AUTH CRAM-MD5\r\n")
		case upper == "AUTH CRAM-MD5":
			write("334 PDEyMzQ1LjY3ODkwQGZha2UuZXhhbXBsZS50ZXN0Pg==\r\n")
		case len(lines) == 3:
			write("235 2.7.0 authentication successful\r\n")
		case strings.HasPrefix(upper, "MAIL FROM:"), strings.HasPrefix(upper, "RCPT TO:"):
			write("250 ok\r\n")
		case upper == "DATA":
			inData = true
			write("354 end with dot\r\n")
		case upper == "QUIT":
			write("221 bye\r\n")
			got <- lines
			return
		default:
			write("500 unexpected\r\n")
		}
	}
}

func fakeSMTPStartTLSServer(t *testing.T, ln net.Listener, certificate tls.Certificate, got chan<- []string) {
	t.Helper()
	conn, err := ln.Accept()
	if err != nil {
		return
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	lines := make([]string, 0, 12)
	write := func(s string) { _, _ = conn.Write([]byte(s)) }
	read := func(reader *bufio.Reader) (string, bool) {
		line, readErr := reader.ReadString('\n')
		if readErr != nil {
			return "", false
		}
		line = strings.TrimRight(line, "\r\n")
		lines = append(lines, line)
		return line, true
	}
	reader := bufio.NewReader(conn)
	write("220 fake.example.test ESMTP\r\n")
	line, ok := read(reader)
	if !ok || !strings.HasPrefix(strings.ToUpper(line), "EHLO ") {
		return
	}
	write("250-fake.example.test\r\n250-STARTTLS\r\n250 AUTH PLAIN\r\n")
	line, ok = read(reader)
	if !ok || strings.ToUpper(line) != "STARTTLS" {
		return
	}
	write("220 ready for TLS\r\n")
	tlsConn := tls.Server(conn, &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{certificate}})
	if err := tlsConn.Handshake(); err != nil {
		return
	}
	reader = bufio.NewReader(tlsConn)
	write = func(s string) { _, _ = tlsConn.Write([]byte(s)) }
	line, ok = read(reader)
	if !ok || !strings.HasPrefix(strings.ToUpper(line), "EHLO ") {
		return
	}
	write("250-fake.example.test\r\n250 AUTH PLAIN\r\n")
	line, ok = read(reader)
	if !ok || !strings.HasPrefix(strings.ToUpper(line), "AUTH PLAIN ") {
		return
	}
	encoded := strings.TrimSpace(line[len("AUTH PLAIN "):])
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil || string(decoded) != "\x00user@example.test\x00smtp-secret" {
		return
	}
	write("235 2.7.0 authentication successful\r\n")
	inData := false
	for {
		line, ok = read(reader)
		if !ok {
			return
		}
		upper := strings.ToUpper(line)
		switch {
		case inData && line == ".":
			inData = false
			write("250 queued\r\n")
		case inData:
		case strings.HasPrefix(upper, "MAIL FROM:"), strings.HasPrefix(upper, "RCPT TO:"):
			write("250 ok\r\n")
		case upper == "DATA":
			inData = true
			write("354 end with dot\r\n")
		case upper == "QUIT":
			write("221 bye\r\n")
			got <- lines
			return
		default:
			write("500 unexpected\r\n")
		}
	}
}

func smtpTestCertificate(t *testing.T, serverName string) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: serverName}, DNSNames: []string{serverName},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certificate := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	roots := x509.NewCertPool()
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots.AddCert(parsed)
	return certificate, roots
}

func fakeSMTPAcceptThenClose(t *testing.T, ln net.Listener) {
	t.Helper()
	conn, err := ln.Accept()
	if err != nil {
		return
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	r := bufio.NewReader(conn)
	write := func(s string) { _, _ = conn.Write([]byte(s)) }
	write("220 fake.example.test ESMTP\r\n")
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		switch upper := strings.ToUpper(strings.TrimRight(line, "\r\n")); {
		case strings.HasPrefix(upper, "HELO"), strings.HasPrefix(upper, "EHLO"), strings.HasPrefix(upper, "MAIL FROM:"), strings.HasPrefix(upper, "RCPT TO:"):
			write("250 ok\r\n")
		case upper == "DATA":
			write("354 end with dot\r\n")
			for {
				data, err := r.ReadString('\n')
				if err != nil {
					return
				}
				if strings.TrimRight(data, "\r\n") == "." {
					write("250 queued\r\n")
					return
				}
			}
		default:
			write("250 ok\r\n")
		}
	}
}
