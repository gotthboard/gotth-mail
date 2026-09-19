package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"forgejo/gotthboard/gotth-mail/internal/outboundpolicy"
	"forgejo/gotthboard/gotth-mail/internal/postfixgate"
	"forgejo/gotthboard/gotth-mail/internal/version"
)

const exitTempFail = 75

// main validates the build and dispatches one explicit gate mode.
// Complexity: local time and space O(1); mode-specific costs are delegated.
func main() {
	if err := version.Validate(version.Version); err != nil {
		log.Print(err)
		os.Exit(exitTempFail)
	}
	if len(os.Args) < 2 {
		log.Print("Postfix gate mode required")
		os.Exit(exitTempFail)
	}
	switch os.Args[1] {
	case "helper":
		if err := runHelper(); err != nil {
			log.Printf("Postfix helper failed: %v", err)
			os.Exit(exitTempFail)
		}
	case "deliver":
		if err := runDelivery(os.Args[2:], os.Stdin); err != nil {
			log.Printf("Postfix delivery deferred: %v", err)
			os.Exit(exitTempFail)
		}
	default:
		log.Print("unsupported Postfix gate mode")
		os.Exit(exitTempFail)
	}
}

// runHelper serves the narrow local postqueue/postsuper boundary.
// Complexity: startup time and space O(n), Omega(1), where n is bounded
// configuration text; serving cost is delegated to postfixgate.Helper.
func runHelper() error {
	token, err := helperToken()
	if err != nil {
		return err
	}
	releaseToken, err := releaseToken()
	if err != nil {
		return err
	}
	instance := strings.TrimSpace(os.Getenv("GOTTH_MAIL_POSTFIX_INSTANCE"))
	if instance == "" {
		return errors.New("GOTTH_MAIL_POSTFIX_INSTANCE is required")
	}
	boundary := outboundpolicy.PostfixBoundary{
		PostqueuePath:  "/usr/sbin/postqueue",
		PostsuperPath:  "/usr/sbin/postsuper",
		InstanceID:     instance,
		MaxOutputBytes: 8 << 20,
	}
	helper, err := postfixgate.NewHelper(boundary, boundary, boundary, token, releaseToken)
	if err != nil {
		return err
	}
	addr := strings.TrimSpace(os.Getenv("GOTTH_MAIL_POSTFIX_HELPER_LISTEN"))
	if addr == "" {
		addr = ":10026"
	}
	server := &http.Server{
		Addr:              addr,
		Handler:           helper.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       30 * time.Second,
	}
	return server.ListenAndServe()
}

// runDelivery executes one Postfix pipe(8) transport request.
// Complexity: local time and space O(r+n), Omega(r), where r is bounded
// recipients and n argument bytes; delivery costs are delegated to Gate.
func runDelivery(args []string, message io.Reader) error {
	flags := flag.NewFlagSet("deliver", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	var originals, recipients stringList
	queueID := flags.String("queue-id", "", "")
	authenticated := flags.String("authenticated-mailbox", "", "")
	systemSender := flags.String("system-sender-id", "", "")
	flags.Var(&originals, "original-recipient", "")
	flags.Var(&recipients, "recipient", "")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 || len(originals) == 0 || len(originals) != len(recipients) {
		return errors.New("invalid Postfix pipe arguments")
	}
	authenticatedMailbox, systemSenderID, err := deliveryAuthority(*authenticated, *systemSender)
	if err != nil {
		return err
	}
	token, err := helperToken()
	if err != nil {
		return err
	}
	control, err := postfixgate.NewHTTPController(os.Getenv("GOTTH_MAIL_CORE_URL"), token)
	if err != nil {
		return err
	}
	instance := strings.TrimSpace(os.Getenv("GOTTH_MAIL_POSTFIX_INSTANCE"))
	if instance == "" {
		return errors.New("GOTTH_MAIL_POSTFIX_INSTANCE is required")
	}
	boundary := outboundpolicy.PostfixBoundary{PostqueuePath: "/usr/sbin/postqueue", PostsuperPath: "/usr/sbin/postsuper", InstanceID: instance, MaxOutputBytes: 8 << 20}
	deliveries := make([]outboundpolicy.QueueDelivery, len(recipients))
	for i := range recipients {
		deliveries[i] = outboundpolicy.QueueDelivery{OriginalRecipient: originals[i], Recipient: recipients[i]}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	gate := postfixgate.Gate{
		Inspector: boundary,
		Control:   control,
		Relay: postfixgate.SMTPRelay{
			Addr:      os.Getenv("GOTTH_MAIL_OUTBOUND_RELAY_ADDR"),
			HelloName: instance,
			Timeout:   30 * time.Second,
		},
	}
	return gate.Deliver(ctx, postfixgate.DeliveryRequest{
		QueueID:              *queueID,
		AuthenticatedMailbox: authenticatedMailbox,
		SystemSenderID:       systemSenderID,
		Deliveries:           deliveries,
	}, message)
}

// deliveryAuthority maps Postfix's authenticated SASL identity onto exactly
// one durable authority class. System senders authenticate with their stable
// `system:` object ID; ordinary identities remain mailbox addresses.
// Complexity: time O(n), Omega(1); auxiliary space O(1), where n is bounded
// identity text.
func deliveryAuthority(authenticated, explicitSystem string) (string, string, error) {
	if authenticated != "" && explicitSystem != "" {
		return "", "", errors.New("ambiguous Postfix delivery authority")
	}
	if explicitSystem != "" {
		return "", explicitSystem, nil
	}
	if strings.HasPrefix(authenticated, "system:") {
		return "", authenticated, nil
	}
	return authenticated, "", nil
}

type stringList []string

// String reports only the value count so secrets and addresses cannot leak.
// Complexity: time and auxiliary space O(1).
func (s *stringList) String() string { return fmt.Sprintf("%d values", len(*s)) }

// Set appends one bounded non-empty Postfix address argument.
// Complexity: amortized time O(n), Omega(1); auxiliary space O(n), where n is
// the bounded value length.
func (s *stringList) Set(value string) error {
	if value == "" || len(value) > 320 {
		return errors.New("invalid Postfix address argument")
	}
	*s = append(*s, value)
	return nil
}

// helperToken reads one bounded direct or file-backed shared secret.
// Complexity: time and auxiliary space O(n), Omega(1), where n is capped at
// 4097 bytes; file mode performs one bounded read.
func helperToken() (string, error) {
	return configuredGateSecret("GOTTH_MAIL_POSTFIX_HELPER_TOKEN", "GOTTH_MAIL_POSTFIX_HELPER_TOKEN_FILE", "Postfix helper token")
}

// releaseToken reads the independent credential unavailable to pipe services.
// Complexity: time and auxiliary space O(n), Omega(1), where n is capped at
// 4097 bytes; file mode performs one bounded read.
func releaseToken() (string, error) {
	return configuredGateSecret("GOTTH_MAIL_POSTFIX_RELEASE_TOKEN", "GOTTH_MAIL_POSTFIX_RELEASE_TOKEN_FILE", "Postfix release token")
}

// configuredGateSecret reads one bounded direct or file-backed credential.
// Complexity: time and auxiliary space O(n), Omega(1), where n is capped at
// 4097 bytes; file mode performs one bounded read.
func configuredGateSecret(valueName, fileName, label string) (string, error) {
	direct := os.Getenv(valueName)
	path := strings.TrimSpace(os.Getenv(fileName))
	if direct != "" && path != "" {
		return "", errors.New(label + " sources are mutually exclusive")
	}
	if path == "" {
		if len(direct) < 32 || len(direct) > 4096 {
			return "", errors.New("invalid " + label)
		}
		return direct, nil
	}
	handle, err := os.Open(path)
	if err != nil {
		return "", errors.New(label + " file unavailable")
	}
	defer handle.Close()
	data, err := io.ReadAll(io.LimitReader(handle, 4097))
	if err != nil || len(data) > 4096 {
		return "", errors.New("invalid " + label + " file")
	}
	token := strings.TrimRight(string(data), "\r\n")
	if len(token) < 32 || len(token) > 4096 {
		return "", errors.New("invalid " + label)
	}
	return token, nil
}
