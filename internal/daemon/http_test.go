package daemon

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHTTPDaemonRoutes(t *testing.T) {
	mux := http.NewServeMux()
	fixture().Register(mux)
	for _, tc := range []struct {
		method string
		path   string
		body   string
		want   Decision
	}{
		{http.MethodGet, "/internal/v1/postfix/domains/example.test", "", OK},
		{http.MethodGet, "/internal/v1/postfix/recipients/missing@example.test", "", NotFound},
		{http.MethodGet, "/internal/v1/postfix/aliases/alias@example.test", "", OK},
		{http.MethodPost, "/internal/v1/postfix/sender-login", `{"sasl_username":"user@example.test","mail_from":"user@example.test","client_ip":"192.0.2.10"}`, OK},
		{http.MethodPost, "/internal/v1/postfix/outbound-policy", `{"stage":"submission","authenticated_mailbox":"user@example.test","envelope_sender":"user@example.test","recipient":"outside@example.net"}`, Defer},
		{http.MethodGet, "/internal/v1/dovecot/userdb/user@example.test", "", OK},
		{http.MethodPost, "/internal/v1/dovecot/passdb", `{"username":"user@example.test","secret":"app-secret","protocol":"imap"}`, OK},
		{http.MethodGet, "/internal/v1/rspamd/local-domains", "", OK},
		{http.MethodGet, "/internal/v1/rspamd/dkim/example.test", "", OK},
		{http.MethodPost, "/internal/v1/rspamd/signing-decision", `{"domain":"example.test"}`, OK},
	} {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(tc.method, tc.path, bytes.NewBufferString(tc.body))
		req.Header.Set("X-Correlation-ID", "test-correlation")
		mux.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("%s %s HTTP %d body=%s", tc.method, tc.path, rr.Code, rr.Body.String())
		}
		var got Response
		if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
			t.Fatal(err)
		}
		if got.Decision != tc.want || got.CorrelationID != "test-correlation" {
			t.Fatalf("%s %s got %#v", tc.method, tc.path, got)
		}
	}
}

func TestHTTPOutboundPolicyRejectsCallerSuppliedGoverningDomains(t *testing.T) {
	mux := http.NewServeMux()
	fixture().Register(mux)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/internal/v1/postfix/outbound-policy", bytes.NewBufferString(`{"stage":"submission","recipient":"outside@example.net","governing":[{"domain":"example.test","scope":"unrestricted","revision":1}]}`))
	mux.ServeHTTP(rr, req)
	var got Response
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Decision != Error || got.Reason != "malformed_json" {
		t.Fatalf("caller authority accepted: %#v", got)
	}
}

func TestHTTPDaemonMethodAndMalformedJSON(t *testing.T) {
	mux := http.NewServeMux()
	fixture().Register(mux)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/internal/v1/postfix/domains/example.test", nil))
	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("method status=%d", rr.Code)
	}
	rr = httptest.NewRecorder()
	mux.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/internal/v1/dovecot/passdb", bytes.NewBufferString(`{`)))
	var got Response
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Decision != Error || got.Reason != "malformed_json" {
		t.Fatalf("malformed got %#v", got)
	}
}
