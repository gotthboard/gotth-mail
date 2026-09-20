package frontauth

import (
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
			"Auth-User": "user@example.test", "Auth-Pass": "mail-secret",
		})
		if w.Code != http.StatusOK || w.Header().Get("Auth-Status") != "OK" {
			t.Fatalf("%s response: code=%d headers=%v", protocol, w.Code, w.Header())
		}
		wantServer := "dovecot"
		if protocol == "smtp" {
			wantServer = "postfix"
		}
		if got := w.Header().Get("Auth-Server"); got != wantServer {
			t.Fatalf("%s server=%q", protocol, got)
		}
	}
}

func TestUnauthenticatedSMTPChecksRecipient(t *testing.T) {
	h := testHandler(t)
	accepted := request(t, h, map[string]string{
		"Auth-Protocol": "smtp", "Auth-Method": "none", "Auth-SMTP-To": "user@example.test",
	})
	if accepted.Header().Get("Auth-Status") != "OK" || accepted.Header().Get("Auth-Server") != "postfix" {
		t.Fatalf("accepted headers=%v", accepted.Header())
	}
	rejected := request(t, h, map[string]string{
		"Auth-Protocol": "smtp", "Auth-Method": "none", "Auth-SMTP-To": "missing@example.test",
	})
	if rejected.Header().Get("Auth-Status") != "authentication failed" || rejected.Header().Get("Auth-Server") != "" {
		t.Fatalf("rejected headers=%v", rejected.Header())
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
