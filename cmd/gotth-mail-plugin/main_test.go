package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/mail"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"forgejo/gotthboard/gotth-mail/internal/notification"
	"forgejo/gotthboard/gotth-mail/internal/notifyruntime"
	"forgejo/gotthboard/gotth-mail/internal/outboundpolicy"
	"forgejo/gotthboard/gotth-mail/internal/plugin"
	"forgejo/gotthboard/gotth-mail/internal/webmail"
	pluginv1 "forgejo/gotthboard/gotth-mail/proto/gotth/mail/plugin/v1"
	protonpgp "github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

func TestNotificationSinkForKeepsLocalTelegramSinkFixtureOnly(t *testing.T) {
	sink, err := notificationSinkFor(plugin.FirstNotifyName, func(name string) string {
		if name == "GOTTH_MAIL_REFERENCE_FIXTURE" {
			return "1"
		}
		return ""
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := sink.(plugin.LocalNotificationSink); !ok {
		t.Fatalf("telegram sink = %T, want plugin.LocalNotificationSink", sink)
	}
}

func TestNotificationSinkForRequiresTelegramProductionConfig(t *testing.T) {
	if _, err := notificationSinkFor(plugin.FirstNotifyName, func(string) string { return "" }); err == nil || !strings.Contains(err.Error(), "bot token") {
		t.Fatalf("missing Telegram config accepted: %v", err)
	}
}

func TestNotificationSinkForSignedEmailRequiresExplicitConfig(t *testing.T) {
	if _, err := notificationSinkFor(plugin.FirstEmailName, func(name string) string {
		if name == "GOTTH_MAIL_OUTBOUND_POLICY_URL" {
			return "http://127.0.0.1/internal/v1/postfix/outbound-policy"
		}
		return ""
	}); err == nil || !strings.Contains(err.Error(), "from required") {
		t.Fatalf("missing signed email config accepted: %v", err)
	}
}

func TestNotificationSinkForRejectsUnknownNotificationName(t *testing.T) {
	if _, err := notificationSinkFor("unknown-notification", func(string) string { return "" }); err == nil || !strings.Contains(err.Error(), "not wired") {
		t.Fatalf("unknown notification sink accepted: %v", err)
	}
}

func TestNotificationSMTPPasswordSupportsPrivateFileAndRejectsAmbiguity(t *testing.T) {
	path := filepath.Join(t.TempDir(), "smtp-password")
	if err := os.WriteFile(path, []byte("file-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	secret, err := notificationSMTPPassword(func(name string) string {
		if name == "GOTTH_MAIL_NOTIFICATION_EMAIL_SMTP_PASSWORD_FILE" {
			return path
		}
		return ""
	})
	if err != nil || secret != "file-secret" {
		t.Fatalf("file secret=%q err=%v", secret, err)
	}
	if _, err := notificationSMTPPassword(func(name string) string {
		switch name {
		case "GOTTH_MAIL_NOTIFICATION_EMAIL_SMTP_PASSWORD":
			return "direct-secret"
		case "GOTTH_MAIL_NOTIFICATION_EMAIL_SMTP_PASSWORD_FILE":
			return path
		default:
			return ""
		}
	}); err == nil {
		t.Fatal("accepted ambiguous direct and file SMTP secrets")
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := notificationSMTPPassword(func(name string) string {
		if name == "GOTTH_MAIL_NOTIFICATION_EMAIL_SMTP_PASSWORD_FILE" {
			return path
		}
		return ""
	}); err == nil {
		t.Fatal("accepted group/world-readable SMTP secret file")
	}
}

func TestNotificationSinkForSignedEmailBuildsWorkingAdapter(t *testing.T) {
	now := time.Now().UTC()
	_, keyPath, fingerprint := writePluginSigningKey(t, now)
	env := map[string]string{
		"GOTTH_MAIL_NOTIFICATION_EMAIL_FROM":                "alerts@example.test",
		"GOTTH_MAIL_NOTIFICATION_EMAIL_TO":                  "ops@example.test",
		"GOTTH_MAIL_NOTIFICATION_EMAIL_SIGNING_FINGERPRINT": fingerprint,
		"GOTTH_MAIL_NOTIFICATION_EMAIL_PRIVATE_KEY_FILE":    keyPath,
		"GOTTH_MAIL_NOTIFICATION_EMAIL_SMTP_ADDR":           "127.0.0.1:2525",
		"GOTTH_MAIL_NOTIFICATION_EMAIL_SMTP_USERNAME":       "system:alerts@example.test",
		"GOTTH_MAIL_NOTIFICATION_EMAIL_SMTP_PASSWORD":       "smtp-secret",
		"GOTTH_MAIL_OUTBOUND_POLICY_URL":                    "http://127.0.0.1/internal/v1/postfix/outbound-policy",
	}
	sink, err := notificationSinkFor(plugin.FirstEmailName, func(name string) string { return env[name] })
	if err != nil {
		t.Fatal(err)
	}
	emailSink, ok := sink.(signedEmailNotificationSink)
	if !ok {
		t.Fatalf("signed email sink = %T", sink)
	}
	smtp := &pluginDirectCaptureSMTP{}
	emailSink.backend.SMTP = smtp
	emailSink.backend.Policy = pluginAllowPolicy{}
	result, err := emailSink.SendAlert(context.Background(), notification.Alert{ID: "direct-alert", Class: "backup.failure", Severity: notification.SeverityCritical, Title: "Backup failed", Summary: "verification failed"})
	if err != nil || result.Status != notification.StatusDelivered || smtp.calls != 1 {
		t.Fatalf("direct signed email adapter result=%#v err=%v SMTP calls=%d", result, err, smtp.calls)
	}
	if _, err := emailSink.SendPrompt(context.Background(), plugin.NotificationPrompt{}); status.Code(err) != codes.Unimplemented {
		t.Fatalf("direct signed email prompt error = %v", err)
	}
}

type pluginDirectCaptureSMTP struct {
	calls int
}

func (s *pluginDirectCaptureSMTP) Submit(context.Context, webmail.Envelope, []byte) error {
	s.calls++
	return nil
}

func TestSignedEmailNotificationSinkGRPCDeliversCryptographicallyVerifiedSMTPAndRejectsPrompt(t *testing.T) {
	now := time.Unix(1700000000, 0).UTC()
	_, keyPath, fingerprint := writePluginSigningKey(t, now)
	smtpAddr, captures := startPluginCaptureSMTP(t)
	policyServer := startPluginAllowPolicyServer(t)
	defer policyServer.Close()
	endpoint := reservePluginEndpoint(t)
	logPath, stop := startPluginProcess(t, endpoint, map[string]string{
		"GOTTH_MAIL_PLUGIN_NAME":                            plugin.FirstEmailName,
		"GOTTH_MAIL_PLUGIN_SERVICE_TOKEN":                   "tok",
		"GOTTH_MAIL_PLUGIN_LISTEN":                          endpoint,
		"GOTTH_MAIL_NOTIFICATION_EMAIL_FROM":                "alerts@example.test",
		"GOTTH_MAIL_NOTIFICATION_EMAIL_TO":                  "ops@example.test",
		"GOTTH_MAIL_NOTIFICATION_EMAIL_SIGNING_FINGERPRINT": fingerprint,
		"GOTTH_MAIL_NOTIFICATION_EMAIL_PRIVATE_KEY_FILE":    keyPath,
		"GOTTH_MAIL_NOTIFICATION_EMAIL_SMTP_ADDR":           smtpAddr,
		"GOTTH_MAIL_NOTIFICATION_EMAIL_SMTP_USERNAME":       "system:alerts@example.test",
		"GOTTH_MAIL_NOTIFICATION_EMAIL_SMTP_PASSWORD":       "smtp-secret",
		"GOTTH_MAIL_OUTBOUND_POLICY_URL":                    policyServer.URL,
	})
	defer stop()
	conn, err := waitForPluginProcess(endpoint, "tok", 10*time.Second)
	if err != nil {
		stop()
		log, _ := os.ReadFile(logPath)
		t.Fatalf("real gotth-mail-plugin endpoint did not become ready: %v\n%s", err, log)
	}
	t.Cleanup(func() { _ = conn.Close() })
	client := pluginv1.NewNotificationBackendClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	ctx = metadata.NewOutgoingContext(ctx, metadata.Pairs(plugin.MetadataCorrelationID, "corr-email-1", plugin.MetadataServiceToken, "tok"))
	version, err := plugin.NewControlClient(conn).Version(ctx, &pluginv1.VersionRequest{CorrelationId: "corr-email-1"})
	if err != nil {
		t.Fatal(err)
	}
	if version.GetName() != plugin.FirstEmailName {
		t.Fatalf("real plugin process name = %q, want %q", version.GetName(), plugin.FirstEmailName)
	}
	response, err := client.SendAlert(ctx, &pluginv1.SendAlertRequest{Alert: &pluginv1.AlertMessage{
		Id:            "alert-email-1",
		Class:         "backup.failure",
		Severity:      "critical",
		Title:         "Backup café failed",
		Summary:       "naïve résumé verification failed",
		CorrelationId: "corr-email-1",
		Resource:      &pluginv1.AlertResource{Type: "backup", Id: "artifact-1"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if response.GetStatus() != "delivered" || !strings.Contains(response.GetReason(), "signed_email_delivered") {
		t.Fatalf("bad delivery response: %#v", response)
	}
	evidence := response.GetEvidence()
	if evidence == nil {
		t.Fatal("delivered response omitted signed-email evidence")
	}
	if evidence.GetTransport() != "email" ||
		evidence.GetFrom() != "alerts@example.test" ||
		evidence.GetSigningFingerprint() != fingerprint ||
		evidence.GetSenderIdentityId() != "system:alerts@example.test" ||
		evidence.GetSenderIdentityClass() != "system" ||
		evidence.GetPolicyVersion() != notifyruntime.SignedEmailPolicyVersion ||
		evidence.GetIdentityStateRef() != "openpgp:"+fingerprint ||
		evidence.GetVerificationResult() != notifyruntime.VerificationValidExactSender ||
		evidence.GetWorkflow() != notifyruntime.SignedEmailWorkflow ||
		evidence.GetMessageId() == "" {
		t.Fatalf("incomplete signed-email delivery evidence: %#v", evidence)
	}
	generatedAt, err := time.Parse(time.RFC3339Nano, evidence.GetGeneratedAt())
	if err != nil || generatedAt.IsZero() || time.Since(generatedAt) > time.Minute || generatedAt.After(time.Now().Add(time.Second)) {
		t.Fatalf("invalid signed-email evidence generated_at %q: %v", evidence.GetGeneratedAt(), err)
	}
	var capture pluginSMTPCapture
	select {
	case capture = <-captures:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	if capture.authUser != "system:alerts@example.test" || !strings.Contains(capture.mailFrom, "alerts@example.test") || !strings.Contains(capture.rcptTo, "ops@example.test") {
		t.Fatalf("bad SMTP envelope: %#v", capture)
	}
	for i, value := range capture.body {
		if value > 0x7f {
			t.Fatalf("captured SMTP body contains non-7-bit byte %#x at offset %d", value, i)
		}
	}
	identity := webmail.Identity{Address: "alerts@example.test", Fingerprint: fingerprint}
	keyFile, err := os.Open(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := protonpgp.ReadArmoredKeyRing(keyFile)
	_ = keyFile.Close()
	if err != nil {
		t.Fatal(err)
	}
	verified, err := (webmail.OpenPGPMIMEVerifier{KeyRing: loaded, Now: func() time.Time { return time.Now().UTC() }}).VerifyExactSender(context.Background(), capture.body, identity)
	if err != nil {
		t.Fatalf("captured SMTP message did not verify: %v\n%s", err, capture.body)
	}
	if !verified.Signed || verified.Identity != identity.Address || verified.Fingerprint != identity.Fingerprint {
		t.Fatalf("bad exact-sender verification: %#v", verified)
	}
	wireMessage, err := mail.ReadMessage(bytes.NewReader(capture.body))
	if err != nil {
		t.Fatalf("read captured signed MIME headers: %v", err)
	}
	if got := wireMessage.Header.Get("Message-ID"); got != evidence.GetMessageId() {
		t.Fatalf("evidence Message-ID = %q, captured signed MIME = %q", evidence.GetMessageId(), got)
	}
	if _, err := client.SendPrompt(ctx, &pluginv1.SendPromptRequest{Id: "prompt-email-1", CorrelationId: "corr-email-1"}); status.Code(err) != codes.Unimplemented {
		t.Fatalf("signed email prompt error = %v, want unimplemented", err)
	}
}

type pluginAllowPolicy struct{}

func (pluginAllowPolicy) Decide(context.Context, string, outboundpolicy.EnforcementRequest) (outboundpolicy.Decision, error) {
	return outboundpolicy.Decision{Action: outboundpolicy.ActionOK, Reason: outboundpolicy.ReasonUnrestricted}, nil
}

func startPluginAllowPolicyServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request outboundpolicy.EnforcementRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		if request.SystemSenderID != "system:alerts@example.test" {
			http.Error(w, "bad authority", http.StatusBadRequest)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"correlation_id": r.Header.Get("X-Correlation-ID"),
			"decision":       "ok", "reason": "outbound_scope_unrestricted",
		})
	}))
}

func reservePluginEndpoint(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	endpoint := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	return endpoint
}

func startPluginProcess(t *testing.T, endpoint string, values map[string]string) (string, func()) {
	t.Helper()
	repo := pluginRepoRoot(t)
	binary := filepath.Join(t.TempDir(), "gotth-mail-plugin")
	build := exec.Command("go", "build", "-o", binary, "./cmd/gotth-mail-plugin")
	build.Dir = repo
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build real gotth-mail-plugin: %v\n%s", err, output)
	}
	logFile, err := os.CreateTemp(t.TempDir(), "gotth-mail-plugin-process-*.log")
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command(binary)
	command.Dir = repo
	command.Stdout = logFile
	command.Stderr = logFile
	command.Env = cleanPluginProcessEnvironment(values)
	if err := command.Start(); err != nil {
		_ = logFile.Close()
		t.Fatal(err)
	}
	stopped := false
	stop := func() {
		if stopped {
			return
		}
		stopped = true
		_ = command.Process.Kill()
		_ = command.Wait()
		_ = logFile.Close()
	}
	t.Cleanup(stop)
	return logFile.Name(), stop
}

func cleanPluginProcessEnvironment(values map[string]string) []string {
	env := make([]string, 0, len(os.Environ())+len(values))
	for _, entry := range os.Environ() {
		name, _, _ := strings.Cut(entry, "=")
		if strings.HasPrefix(name, "GOTTH_MAIL_PLUGIN_") || strings.HasPrefix(name, "GOTTH_MAIL_NOTIFICATION_EMAIL_") {
			continue
		}
		env = append(env, entry)
	}
	for name, value := range values {
		env = append(env, name+"="+value)
	}
	return env
}

func pluginRepoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("repository root not found")
		}
		dir = parent
	}
}

func waitForPluginProcess(endpoint, token string, timeout time.Duration) (*grpc.ClientConn, error) {
	conn, err := grpc.NewClient(endpoint, grpc.WithInsecure())
	if err != nil {
		return nil, err
	}
	client := plugin.NewControlClient(conn)
	deadline := time.Now().Add(timeout)
	var lastErr error
	for time.Now().Before(deadline) {
		ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
		ctx = metadata.NewOutgoingContext(ctx, metadata.Pairs(plugin.MetadataCorrelationID, "process-readiness", plugin.MetadataServiceToken, token))
		response, err := client.Health(ctx, &pluginv1.HealthRequest{CorrelationId: "process-readiness"})
		cancel()
		if err == nil && response.GetHealthy() {
			return conn, nil
		}
		lastErr = err
		time.Sleep(25 * time.Millisecond)
	}
	_ = conn.Close()
	return nil, fmt.Errorf("timed out waiting for %s: %w", endpoint, lastErr)
}

type pluginSMTPCapture struct {
	authUser string
	mailFrom string
	rcptTo   string
	body     []byte
}

func startPluginCaptureSMTP(t *testing.T) (string, <-chan pluginSMTPCapture) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	captures := make(chan pluginSMTPCapture, 1)
	errors := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			errors <- err
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
		reader := bufio.NewReader(conn)
		write := func(line string) error { _, err := conn.Write([]byte(line)); return err }
		if err := write("220 capture.example.test ESMTP\r\n"); err != nil {
			errors <- err
			return
		}
		var capture pluginSMTPCapture
		awaitingCRAM := false
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				errors <- err
				return
			}
			command := strings.TrimRight(line, "\r\n")
			upper := strings.ToUpper(command)
			switch {
			case awaitingCRAM:
				awaitingCRAM = false
				var decoded []byte
				decoded, err = base64.StdEncoding.DecodeString(command)
				if err == nil {
					capture.authUser = strings.SplitN(string(decoded), " ", 2)[0]
					err = write("235 2.7.0 authentication successful\r\n")
				}
			case strings.HasPrefix(upper, "EHLO "), strings.HasPrefix(upper, "HELO "):
				err = write("250-capture.example.test\r\n250 AUTH CRAM-MD5\r\n")
			case upper == "AUTH CRAM-MD5":
				awaitingCRAM = true
				err = write("334 PDEyMzQ1LjY3ODkwQGNhcHR1cmUuZXhhbXBsZS50ZXN0Pg==\r\n")
			case strings.HasPrefix(upper, "MAIL FROM:"):
				if capture.authUser != "system:alerts@example.test" {
					err = write("530 authentication required\r\n")
				} else {
					capture.mailFrom = command
					err = write("250 ok\r\n")
				}
			case strings.HasPrefix(upper, "RCPT TO:"):
				capture.rcptTo = command
				err = write("250 ok\r\n")
			case upper == "DATA":
				if err = write("354 end with dot\r\n"); err == nil {
					capture.body, err = readPluginSMTPData(reader)
				}
				if err == nil {
					err = write("250 queued\r\n")
				}
			case upper == "QUIT":
				if err = write("221 bye\r\n"); err == nil {
					captures <- capture
				}
				if err != nil {
					errors <- err
				}
				return
			default:
				err = write("250 ok\r\n")
			}
			if err != nil {
				errors <- err
				return
			}
		}
	}()
	t.Cleanup(func() {
		select {
		case err := <-errors:
			if !strings.Contains(err.Error(), "use of closed network connection") {
				t.Errorf("capture SMTP server: %v", err)
			}
		default:
		}
	})
	return listener.Addr().String(), captures
}

func readPluginSMTPData(reader *bufio.Reader) ([]byte, error) {
	var body bytes.Buffer
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return nil, err
		}
		if line == ".\r\n" || line == ".\n" {
			return body.Bytes(), nil
		}
		if strings.HasPrefix(line, "..") {
			line = line[1:]
		}
		body.WriteString(line)
	}
}

func writePluginSigningKey(t *testing.T, now time.Time) (*protonpgp.Entity, string, string) {
	t.Helper()
	entity, err := protonpgp.NewEntity("Alert Sender", "", "alerts@example.test", &packet.Config{Algorithm: packet.PubKeyAlgoEdDSA, DefaultHash: crypto.SHA256, Time: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	path := t.TempDir() + "/notification-private-key.asc"
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	block, err := armor.Encode(f, protonpgp.PrivateKeyType, nil)
	if err != nil {
		_ = f.Close()
		t.Fatal(err)
	}
	if err := entity.SerializePrivateWithoutSigning(block, nil); err != nil {
		_ = block.Close()
		_ = f.Close()
		t.Fatal(err)
	}
	if err := block.Close(); err != nil {
		_ = f.Close()
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	fingerprint := strings.ToUpper(fmt.Sprintf("%X", entity.PrimaryKey.Fingerprint))
	return entity, path, fingerprint
}
