package api

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"forgejo/linus/gophermailforge/internal/authz"
	"forgejo/linus/gophermailforge/internal/config"
	"forgejo/linus/gophermailforge/internal/daemon"
	"forgejo/linus/gophermailforge/internal/ops"
	"forgejo/linus/gophermailforge/internal/plugin"
)

func TestV0APIShellRoutes(t *testing.T) {
	cfg, err := config.Parse(`server:
  public_url: "https://mail.example.test"
  listen: ":8080"
  environment: "development"
database:
  dsn: "postgres://db"
tls:
  mode: "manual"
  cert_path: "cert.pem"
  key_path: "key.pem"
authentik:
  enabled: true
  base_url: "https://auth.example.test"
  oidc_client_id: "gmf"
  scim_base_url: "https://auth.example.test/scim"
roles:
  global_admin_group: "admins"
  domain_manager_group: "managers"
  scoped_domain_group_prefix: "domain-"
render:
  staging_dir: "var/staged"
  applied_dir: "var/applied"
plugins:
  - name: "stub-dns"
    seam: "dns"
    image: "stub:v0"
    endpoint: "dns:9443"
`)
	if err != nil {
		t.Fatal(err)
	}
	h := Server{Authz: authz.StaticAuthorizer{}, Config: cfg, Plugins: plugin.Registry{Plugins: map[string]plugin.Registration{"stub-dns": {Name: "stub-dns", Enabled: true, ServiceToken: "tok", Capabilities: []string{"dns.lookup"}}}}, Daemon: daemon.Service{Domains: map[string]daemon.Domain{"example.test": {Name: "example.test", Enabled: true}}, Mailboxes: map[string]daemon.Mailbox{"postmaster@example.test": {Address: "postmaster@example.test", Enabled: true}}}, Queue: &ops.Queue{Summary: ops.QueueSummary{Active: 1, Deferred: []string{"abc"}}}}.Handler()
	for _, tc := range []struct{ method, path string }{
		{http.MethodGet, "/healthz"},
		{http.MethodGet, "/readyz"},
		{http.MethodGet, "/api/v1/status"},
		{http.MethodGet, "/api/v1/config/effective"},
		{http.MethodPost, "/api/v1/config/render"},
		{http.MethodGet, "/api/v1/audit/events"},
		{http.MethodPost, "/api/v1/authz/explain"},
		{http.MethodGet, "/api/v1/plugins"},
		{http.MethodGet, "/api/v1/plugins/stub-dns/health"},
		{http.MethodGet, "/internal/v1/postfix/domains/example.test"},
		{http.MethodGet, "/internal/v1/rspamd/local-domains"},
		{http.MethodGet, "/api/v1/doctor"},
		{http.MethodGet, "/api/v1/debug/lookup?kind=recipient&value=postmaster@example.test"},
		{http.MethodGet, "/api/v1/queue/summary"},
		{http.MethodGet, "/api/v1/queue/deferred"},
	} {
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, httptest.NewRequest(tc.method, tc.path, nil))
		if rr.Code != http.StatusOK {
			t.Fatalf("%s %s status %d", tc.method, tc.path, rr.Code)
		}
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/v1/config/render", nil))
	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("method gate status %d", rr.Code)
	}
}

func TestOIDCLoginRouteRequiresBrowserBinding(t *testing.T) {
	h := Server{}.Handler()
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/v1/oidc/login", nil))
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("missing browser binding status %d", rr.Code)
	}
}
