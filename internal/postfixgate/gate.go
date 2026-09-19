package postfixgate

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/mail"
	"net/smtp"
	"strings"
	"time"

	"forgejo/gotthboard/gotth-mail/internal/outboundpolicy"
)

const MaxMessageBytes = 64 << 20

type DeliveryRequest struct {
	QueueID              string
	AuthenticatedMailbox string
	SystemSenderID       string
	Deliveries           []outboundpolicy.QueueDelivery
}

type QueueInspector interface {
	Inspect(context.Context, string) (outboundpolicy.QueueMetadata, error)
}

type Controller interface {
	Register(context.Context, outboundpolicy.QueueAdmissionRequest) error
	Decide(context.Context, string, string) (outboundpolicy.Decision, error)
	Reconcile(context.Context, string) error
}

type Relay interface {
	Submit(context.Context, string, []string, []byte) error
}

type Gate struct {
	Inspector QueueInspector
	Control   Controller
	Relay     Relay
}

// Deliver binds live Postfix metadata to authoritative provenance, rechecks
// every remaining recipient, reconciles a whole-message hold on any forbidden
// recipient, and only then hands the bounded message to the configured relay.
// Complexity: time O(r*(p+n)+m), Omega(r+m); auxiliary space O(r+m), where r
// is bounded recipients, p policy latency, n address bytes, and m message bytes
// capped at 64 MiB.
func (g Gate) Deliver(ctx context.Context, request DeliveryRequest, message io.Reader) error {
	if g.Inspector == nil || g.Control == nil || g.Relay == nil || len(request.Deliveries) == 0 {
		return errors.New("Postfix delivery gate is unavailable")
	}
	metadata, err := g.Inspector.Inspect(ctx, request.QueueID)
	if err != nil || metadata.Held {
		return errors.New("Postfix queue metadata is unavailable")
	}
	if err := g.Control.Register(ctx, outboundpolicy.QueueAdmissionRequest{
		Metadata:             metadata,
		AuthenticatedMailbox: request.AuthenticatedMailbox,
		SystemSenderID:       request.SystemSenderID,
		Deliveries:           append([]outboundpolicy.QueueDelivery(nil), request.Deliveries...),
	}); err != nil {
		return err
	}
	for _, recipient := range metadata.Recipients {
		decision, err := g.Control.Decide(ctx, metadata.QueueID, recipient)
		if err != nil {
			return err
		}
		if decision.Action == outboundpolicy.ActionDefer && decision.Reason == outboundpolicy.ReasonPolicyHold {
			if err := g.Control.Reconcile(ctx, metadata.QueueID); err != nil {
				return err
			}
			return errors.New("outbound queue placed on policy hold")
		}
		if decision.Action != outboundpolicy.ActionOK {
			return errors.New("outbound policy deferred final handoff")
		}
	}
	body, err := io.ReadAll(io.LimitReader(message, MaxMessageBytes+1))
	if err != nil || len(body) == 0 || len(body) > MaxMessageBytes {
		return errors.New("invalid or oversized Postfix message")
	}
	return g.Relay.Submit(ctx, metadata.EnvelopeSender, metadata.Recipients, body)
}

type SMTPRelay struct {
	Addr      string
	HelloName string
	Timeout   time.Duration
}

// Submit performs one bounded plaintext SMTP handoff to a trusted configured
// relay. Postfix retains retry authority until the relay accepts DATA.
// Complexity: time O(r+n+m), Omega(r+m); auxiliary space O(r+n), where r is
// recipients, n address bytes, and m message bytes written without copying.
func (s SMTPRelay) Submit(ctx context.Context, sender string, recipients []string, message []byte) error {
	addr := strings.TrimSpace(s.Addr)
	if addr == "" || len(recipients) == 0 || len(message) == 0 {
		return errors.New("invalid SMTP relay request")
	}
	from := ""
	if sender != "<>" {
		parsed, err := mail.ParseAddress(sender)
		if err != nil {
			return errors.New("invalid SMTP relay sender")
		}
		from = parsed.Address
	}
	canonicalRecipients := make([]string, 0, len(recipients))
	for _, recipient := range recipients {
		parsed, err := mail.ParseAddress(recipient)
		if err != nil {
			return errors.New("invalid SMTP relay recipient")
		}
		canonicalRecipients = append(canonicalRecipients, parsed.Address)
	}
	timeout := s.Timeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	dialer := &smtpDialer{addr: addr, helloName: strings.TrimSpace(s.HelloName), timeout: timeout}
	return dialer.submit(ctx, from, canonicalRecipients, message)
}

type smtpDialer struct {
	addr      string
	helloName string
	timeout   time.Duration
}

// submit owns the SMTP acceptance sequence so the gate can distinguish a
// failed handoff from an accepted DATA followed by a failed QUIT.
// Complexity: time O(r+m), Omega(r+m); auxiliary space O(1), excluding network
// buffers owned by the standard library.
func (d smtpDialer) submit(ctx context.Context, sender string, recipients []string, message []byte) error {
	dialer := net.Dialer{Timeout: d.timeout}
	conn, err := dialer.DialContext(ctx, "tcp", d.addr)
	if err != nil {
		return errors.New("SMTP relay unavailable")
	}
	defer conn.Close()
	deadline := time.Now().Add(d.timeout)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	_ = conn.SetDeadline(deadline)
	client, err := smtp.NewClient(conn, smtpServerName(d.addr))
	if err != nil {
		return errors.New("SMTP relay greeting failed")
	}
	defer client.Close()
	if d.helloName != "" {
		if err := client.Hello(d.helloName); err != nil {
			return errors.New("SMTP relay hello failed")
		}
	}
	if err := client.Mail(sender); err != nil {
		return errors.New("SMTP relay sender rejected")
	}
	for _, recipient := range recipients {
		if err := client.Rcpt(recipient); err != nil {
			return errors.New("SMTP relay recipient rejected")
		}
	}
	writer, err := client.Data()
	if err != nil {
		return errors.New("SMTP relay DATA rejected")
	}
	if _, err := io.Copy(writer, bytes.NewReader(message)); err != nil {
		_ = writer.Close()
		return errors.New("SMTP relay message write failed")
	}
	if err := writer.Close(); err != nil {
		return errors.New("SMTP relay did not accept DATA")
	}
	_ = client.Quit()
	return nil
}

// smtpServerName extracts the host for the SMTP client's greeting state.
// Complexity: time O(n), Omega(1), tight Theta(n); auxiliary space O(n),
// Omega(1), where n is the bounded relay address.
func smtpServerName(address string) string {
	host, _, err := net.SplitHostPort(address)
	if err == nil && host != "" {
		return host
	}
	return address
}
