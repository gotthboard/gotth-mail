package frontauth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"forgejo/gotthboard/gotth-mail/internal/daemon"
)

const testToken = "0123456789abcdef0123456789abcdef"

func testHandler(t *testing.T) *Handler {
	t.Helper()
	verifier := daemon.MakeDjangoPBKDF2SHA256("mail-secret", "salt", 1000)
	h, err := New(daemon.Service{
		Domains: map[string]daemon.Domain{"example.test": {Name: "example.test", Enabled: true}},
		Mailboxes: map[string]daemon.Mailbox{"user@example.test": {
			Address: "user@example.test", Enabled: true, Verifier: verifier,
		}},
	}, testToken)
	if err != nil {
		t.Fatal(err)
	}
	h.resolveBackend = func(_ context.Context, host string) (string, error) {
		return map[string]string{"postfix": "172.30.0.3", "dovecot": "172.30.0.4"}[host], nil
	}
	return h
}

func request(t *testing.T, h *Handler, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, "/internal/v1/front/auth", nil)
	r.Header.Set(serviceTokenHeader, testToken)
	for name, value := range headers {
		r.Header.Set(name, value)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func TestAuthenticatedIMAPAndSMTP(t *testing.T) {
	h := testHandler(t)
	for _, protocol := range []string{"imap", "smtp"} {
		w := request(t, h, map[string]string{
			"Auth-Protocol": protocol, "Auth-Method": "plain",
			"Auth-User": "User@Example.Test", "Auth-Pass": "mail-secret",
		})
		if w.Code != http.StatusOK || w.Header().Get("Auth-Status") != "OK" {
			t.Fatalf("%s response: code=%d headers=%v", protocol, w.Code, w.Header())
		}
		if got := w.Header().Get("Auth-User"); got != "user@example.test" {
			t.Fatalf("%s canonical user=%q", protocol, got)
		}
		wantServer := "172.30.0.4"
		if protocol == "smtp" {
			wantServer = "172.30.0.3"
		}
		if got := w.Header().Get("Auth-Server"); got != wantServer {
			t.Fatalf("%s server=%q", protocol, got)
		}
	}
}

func TestUnauthenticatedSMTPChecksRecipient(t *testing.T) {
	h := testHandler(t)
	for _, recipient := range []string{"user@example.test", "RCPT TO:<user@example.test>", "rcpt to:<user@example.test> NOTIFY=SUCCESS"} {
		accepted := request(t, h, map[string]string{
			"Auth-Protocol": "smtp", "Auth-Method": "none", "Auth-SMTP-To": recipient,
		})
		if accepted.Header().Get("Auth-Status") != "OK" || accepted.Header().Get("Auth-Server") != "172.30.0.3" {
			t.Fatalf("recipient=%q accepted headers=%v", recipient, accepted.Header())
		}
	}
	rejected := request(t, h, map[string]string{
		"Auth-Protocol": "smtp", "Auth-Method": "none", "Auth-SMTP-To": "missing@example.test",
	})
	if rejected.Header().Get("Auth-Status") != "authentication failed" || rejected.Header().Get("Auth-Error-Code") != "550 5.1.1" || rejected.Header().Get("Auth-Server") != "" {
		t.Fatalf("rejected headers=%v", rejected.Header())
	}
	for _, malformed := range []string{"RCPT TO:user@example.test", "RCPT TO:<>", "RCPT TO:<user@example.test>garbage"} {
		response := request(t, h, map[string]string{
			"Auth-Protocol": "smtp", "Auth-Method": "none", "Auth-SMTP-To": malformed,
		})
		if response.Header().Get("Auth-Status") != "invalid recipient" || response.Header().Get("Auth-Error-Code") != "501 5.1.3" {
			t.Fatalf("malformed recipient=%q headers=%v", malformed, response.Header())
		}
	}
}

func TestBackendResolutionFailsClosed(t *testing.T) {
	h := testHandler(t)
	h.resolveBackend = func(context.Context, string) (string, error) { return "", os.ErrNotExist }
	response := request(t, h, map[string]string{
		"Auth-Protocol": "smtp", "Auth-Method": "none", "Auth-SMTP-To": "RCPT TO:<user@example.test>",
	})
	if response.Header().Get("Auth-Status") != "authentication temporarily unavailable" || response.Header().Get("Auth-Wait") != "3" || response.Header().Get("Auth-Error-Code") != "451 4.3.0" || response.Header().Get("Auth-Server") != "" {
		t.Fatalf("headers=%v", response.Header())
	}
}

func TestDaemonUnavailabilityReturnsTemporarySMTPFailure(t *testing.T) {
	h := testHandler(t)
	h.service.Unavailable = true
	for _, headers := range []map[string]string{
		{"Auth-Protocol": "smtp", "Auth-Method": "none", "Auth-SMTP-To": "user@example.test"},
		{"Auth-Protocol": "smtp", "Auth-Method": "plain", "Auth-User": "user@example.test", "Auth-Pass": "mail-secret"},
	} {
		response := request(t, h, headers)
		if response.Header().Get("Auth-Status") != "authentication temporarily unavailable" ||
			response.Header().Get("Auth-Wait") != "3" ||
			response.Header().Get("Auth-Error-Code") != "451 4.3.0" {
			t.Fatalf("headers=%v", response.Header())
		}
	}
}

func TestRejectsBadServiceCredentialMethodsAndSecrets(t *testing.T) {
	h := testHandler(t)
	r := httptest.NewRequest(http.MethodGet, "/internal/v1/front/auth", nil)
	r.Header.Set(serviceTokenHeader, strings.Repeat("x", 32))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusForbidden || strings.Contains(w.Body.String(), testToken) {
		t.Fatalf("response code=%d body=%q", w.Code, w.Body.String())
	}

	oversized := request(t, h, map[string]string{
		"Auth-Protocol": "imap", "Auth-Method": "plain", "Auth-User": strings.Repeat("u", maxHeaderBytes+1), "Auth-Pass": "secret",
	})
	if oversized.Header().Get("Auth-Status") != "invalid credentials" {
		t.Fatalf("headers=%v", oversized.Header())
	}
}

func TestLoadTokenFile(t *testing.T) {
	path := t.TempDir() + "/token"
	if err := os.WriteFile(path, []byte(testToken+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, err := LoadTokenFile(path); err != nil || got != testToken {
		t.Fatalf("token=%q err=%v", got, err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadTokenFile(path); err == nil {
		t.Fatal("public token file accepted")
	}
	if _, err := New(daemon.Service{}, "short"); err == nil {
		t.Fatal("short token accepted")
	}
	if _, err := New(daemon.Service{}, "0123456789abcdef0123456789abcde;"); err == nil {
		t.Fatal("configuration-injection token accepted")
	}
}
