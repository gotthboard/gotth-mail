package webmail

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/mail"
	"net/smtp"
	"strings"
	"time"
)

// NetSMTPSubmitter submits already-built, already-signed MIME bytes to an SMTP server.
// It is deliberately small: policy, signing, sender binding, and recipient validation stay
// in Sender. This type only performs the transport exchange.
type NetSMTPSubmitter struct {
	Addr      string
	HelloName string
	Timeout   time.Duration
}

func (s NetSMTPSubmitter) Submit(ctx context.Context, envelope Envelope, msg []byte) error {
	addr := strings.TrimSpace(s.Addr)
	if addr == "" {
		return errors.New("smtp address required")
	}
	from, err := mail.ParseAddress(envelope.From)
	if err != nil {
		return errors.New("invalid smtp envelope sender")
	}
	if len(envelope.To) == 0 {
		return errors.New("smtp recipient required")
	}
	recipients := make([]string, 0, len(envelope.To))
	for _, raw := range envelope.To {
		rcpt, err := mail.ParseAddress(raw)
		if err != nil {
			return fmt.Errorf("invalid smtp recipient %q", raw)
		}
		recipients = append(recipients, rcpt.Address)
	}
	if len(msg) == 0 {
		return errors.New("smtp message required")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	timeout := s.Timeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	dialer := net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return err
	}
	defer conn.Close()
	deadline := time.Now().Add(timeout)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	_ = conn.SetDeadline(deadline)
	client, err := smtp.NewClient(conn, smtpServerName(addr))
	if err != nil {
		return err
	}
	defer client.Close()
	if hello := strings.TrimSpace(s.HelloName); hello != "" {
		if err := client.Hello(hello); err != nil {
			return err
		}
	}
	if err := client.Mail(from.Address); err != nil {
		return err
	}
	for _, rcpt := range recipients {
		if err := client.Rcpt(rcpt); err != nil {
			return err
		}
	}
	w, err := client.Data()
	if err != nil {
		return err
	}
	if _, err := w.Write(msg); err != nil {
		_ = w.Close()
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return client.Quit()
}

func smtpServerName(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err == nil && host != "" {
		return host
	}
	return addr
}
