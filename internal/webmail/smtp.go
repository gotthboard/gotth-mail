package webmail

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/mail"
	"net/smtp"
	"net/textproto"
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
	Auth      smtp.Auth
}

type SMTPFailureClass string

const (
	SMTPFailurePermanent SMTPFailureClass = "permanent"
	SMTPFailureRetryable SMTPFailureClass = "retryable"
	SMTPFailureAmbiguous SMTPFailureClass = "delivery_ambiguous"
)

type SMTPDeliveryError struct {
	Class SMTPFailureClass
	Phase string
	Err   error
}

func (e *SMTPDeliveryError) Error() string {
	if e == nil {
		return "smtp delivery failed"
	}
	return "smtp " + string(e.Class) + " during " + e.Phase
}

func (e *SMTPDeliveryError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

func (s NetSMTPSubmitter) Submit(ctx context.Context, envelope Envelope, msg []byte) error {
	addr := strings.TrimSpace(s.Addr)
	if addr == "" {
		return smtpFailure(SMTPFailurePermanent, "configuration", errors.New("smtp address required"))
	}
	from, err := mail.ParseAddress(envelope.From)
	if err != nil {
		return smtpFailure(SMTPFailurePermanent, "envelope", errors.New("invalid smtp envelope sender"))
	}
	if len(envelope.To) == 0 {
		return smtpFailure(SMTPFailurePermanent, "envelope", errors.New("smtp recipient required"))
	}
	recipients := make([]string, 0, len(envelope.To))
	for _, raw := range envelope.To {
		rcpt, err := mail.ParseAddress(raw)
		if err != nil {
			return smtpFailure(SMTPFailurePermanent, "envelope", fmt.Errorf("invalid smtp recipient %q", raw))
		}
		recipients = append(recipients, rcpt.Address)
	}
	if len(msg) == 0 {
		return smtpFailure(SMTPFailurePermanent, "message", errors.New("smtp message required"))
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
		return classifySMTPFailure("connect", err, false)
	}
	defer conn.Close()
	deadline := time.Now().Add(timeout)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	_ = conn.SetDeadline(deadline)
	client, err := smtp.NewClient(conn, smtpServerName(addr))
	if err != nil {
		return classifySMTPFailure("greeting", err, false)
	}
	defer client.Close()
	if hello := strings.TrimSpace(s.HelloName); hello != "" {
		if err := client.Hello(hello); err != nil {
			return classifySMTPFailure("hello", err, false)
		}
	}
	if s.Auth != nil {
		if err := client.Auth(s.Auth); err != nil {
			return classifySMTPFailure("authentication", err, false)
		}
	}
	if err := client.Mail(from.Address); err != nil {
		return classifySMTPFailure("mail_from", err, false)
	}
	for _, rcpt := range recipients {
		if err := client.Rcpt(rcpt); err != nil {
			return classifySMTPFailure("rcpt_to", err, false)
		}
	}
	w, err := client.Data()
	if err != nil {
		return classifySMTPFailure("data_command", err, false)
	}
	if _, err := w.Write(msg); err != nil {
		_ = w.Close()
		return classifySMTPFailure("data_write", err, false)
	}
	if err := w.Close(); err != nil {
		return classifySMTPFailure("data_accept", err, true)
	}
	// DATA close returning nil is the SMTP acceptance boundary. A failed QUIT
	// cannot turn an accepted message into a retry without risking duplicates.
	_ = client.Quit()
	return nil
}

func smtpFailure(class SMTPFailureClass, phase string, err error) error {
	return &SMTPDeliveryError{Class: class, Phase: phase, Err: err}
}

func classifySMTPFailure(phase string, err error, ambiguousOnTransportFailure bool) error {
	var protocolErr *textproto.Error
	if errors.As(err, &protocolErr) {
		if protocolErr.Code >= 500 {
			return smtpFailure(SMTPFailurePermanent, phase, err)
		}
		if protocolErr.Code >= 400 {
			return smtpFailure(SMTPFailureRetryable, phase, err)
		}
	}
	if ambiguousOnTransportFailure {
		return smtpFailure(SMTPFailureAmbiguous, phase, err)
	}
	return smtpFailure(SMTPFailureRetryable, phase, err)
}

func smtpServerName(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err == nil && host != "" {
		return host
	}
	return addr
}
