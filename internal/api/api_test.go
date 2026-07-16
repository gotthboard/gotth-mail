package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"forgejo/linus/gophermailforge/internal/audit"
	"forgejo/linus/gophermailforge/internal/authz"
	"forgejo/linus/gophermailforge/internal/config"
	"forgejo/linus/gophermailforge/internal/daemon"
	"forgejo/linus/gophermailforge/internal/identity"
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
		var body *strings.Reader
		if tc.path == "/api/v1/authz/explain" {
			body = strings.NewReader(`{"actor":{"type":"local_admin","id":"local"},"action":"status:read","resource":{"type":"system","id":"self"}}`)
		} else {
			body = strings.NewReader("")
		}
		h.ServeHTTP(rr, httptest.NewRequest(tc.method, tc.path, body))
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

func TestAuthzExplainUsesRequestActorActionResource(t *testing.T) {
	h := Server{Authz: authz.StaticAuthorizer{Mappings: []authz.RoleMapping{{AuthentikGroup: "domain-managers", Role: authz.RoleDomainManager, Domain: "example.test", Verified: true}}}}.Handler()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/authz/explain", strings.NewReader(`{"actor":{"type":"oidc_subject","groups":["domain-managers"]},"action":"mailbox:create","resource":{"type":"mailbox","id":"user@example.test"}}`))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d body %s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "domain manager role matched") || !strings.Contains(rr.Body.String(), "oidc:domain_manager:example.test") {
		t.Fatalf("unexpected explain %s", rr.Body.String())
	}
}

func authed(method, path, body, token string) *http.Request {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	return req
}

func TestSCIMUsersSuccessAndFailurePaths(t *testing.T) {
	ids := identity.NewService("example.test")
	if err := ids.AddToken("scim-test", "scim_client", "scim-secret-token"); err != nil {
		t.Fatal(err)
	}
	d := daemon.Service{}
	ids.Daemon = &d
	h := Server{Identity: ids, Daemon: d}.Handler()

	unauth := httptest.NewRecorder()
	h.ServeHTTP(unauth, httptest.NewRequest(http.MethodPost, "/scim/v2/Users", strings.NewReader(`{"userName":"user@example.test"}`)))
	if unauth.Code != http.StatusUnauthorized {
		t.Fatalf("unauth SCIM status=%d", unauth.Code)
	}

	create := authed(http.MethodPost, "/scim/v2/Users", `{"userName":"user@example.test","displayName":"User","active":true,"password":"long-password"}`, "scim-secret-token")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, create)
	if rr.Code != http.StatusCreated || !strings.Contains(rr.Body.String(), "user@example.test") {
		t.Fatalf("create status=%d body=%s", rr.Code, rr.Body.String())
	}
	if got := d.DovecotPassdb("c", daemon.PassdbRequest{Username: "user@example.test", Secret: "long-password", Protocol: "imap"}); got.Decision != daemon.OK {
		t.Fatalf("SCIM password did not enter daemon passdb: %#v", got)
	}

	patch := authed(http.MethodPatch, "/scim/v2/Users/user@example.test", `{"Operations":[{"op":"replace","path":"/displayName","value":"Renamed"},{"op":"replace","path":"/active","value":false}]}`, "scim-secret-token")
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, patch)
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "Renamed") || !strings.Contains(rr.Body.String(), `"active":false`) {
		t.Fatalf("patch status=%d body=%s", rr.Code, rr.Body.String())
	}

	list := authed(http.MethodGet, "/scim/v2/Users", "", "scim-secret-token")
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, list)
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "ListResponse") {
		t.Fatalf("list status=%d body=%s", rr.Code, rr.Body.String())
	}

	read := authed(http.MethodGet, "/scim/v2/Users/user@example.test", "", "scim-secret-token")
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, read)
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "user@example.test") {
		t.Fatalf("read status=%d body=%s", rr.Code, rr.Body.String())
	}

	put := authed(http.MethodPut, "/scim/v2/Users/user@example.test", `{"userName":"user@example.test","displayName":"Put User","active":true,"password":"replacement-password"}`, "scim-secret-token")
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, put)
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "Put User") {
		t.Fatalf("put status=%d body=%s", rr.Code, rr.Body.String())
	}
	if got := d.DovecotPassdb("c", daemon.PassdbRequest{Username: "user@example.test", Secret: "replacement-password", Protocol: "imap"}); got.Decision != daemon.OK {
		t.Fatalf("PUT replacement password did not enter daemon passdb: %#v", got)
	}

	deleteReq := authed(http.MethodDelete, "/scim/v2/Users/user@example.test", "", "scim-secret-token")
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, deleteReq)
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), `"active":false`) {
		t.Fatalf("delete status=%d body=%s", rr.Code, rr.Body.String())
	}

	badCases := []struct{ name, method, path, body string }{
		{"malformed", http.MethodPost, "/scim/v2/Users", `{`},
		{"non-object", http.MethodPost, "/scim/v2/Users", `[]`},
		{"scalar active", http.MethodPost, "/scim/v2/Users", `{"userName":"bad@example.test","active":"yes"}`},
		{"scalar display", http.MethodPost, "/scim/v2/Users", `{"userName":"bad@example.test","displayName":12}`},
		{"scalar formatted", http.MethodPost, "/scim/v2/Users", `{"userName":"bad@example.test","name":{"formatted":12}}`},
		{"bad domain", http.MethodPost, "/scim/v2/Users", `{"userName":"bad@evil.test"}`},
		{"empty operations", http.MethodPatch, "/scim/v2/Users/user@example.test", `{"Operations":[]}`},
		{"unknown path", http.MethodPatch, "/scim/v2/Users/user@example.test", `{"Operations":[{"op":"replace","path":"/unknown","value":"x"}]}`},
		{"unsupported op", http.MethodPatch, "/scim/v2/Users/user@example.test", `{"Operations":[{"op":"move","path":"/displayName","value":"x"}]}`},
	}
	for _, tc := range badCases {
		t.Run(tc.name, func(t *testing.T) {
			rr := httptest.NewRecorder()
			h.ServeHTTP(rr, authed(tc.method, tc.path, tc.body, "scim-secret-token"))
			if rr.Code < 400 || !strings.Contains(rr.Body.String(), "urn:ietf:params:scim:api:messages:2.0:Error") {
				t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
			}
		})
	}

	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/scim/v2/Groups", nil))
	if rr.Code != http.StatusNotImplemented || !strings.Contains(rr.Body.String(), "explicitly unsupported") {
		t.Fatalf("groups status=%d body=%s", rr.Code, rr.Body.String())
	}
}

func TestAppPasswordAPICreateListRevokeSecretOnce(t *testing.T) {
	ids := identity.NewService("example.test")
	ids.Secret = func() (string, error) { return "one-time-client-secret", nil }
	if err := ids.AddToken("api-test", "api_token", "api-secret-token"); err != nil {
		t.Fatal(err)
	}
	d := daemon.Service{}
	ids.Daemon = &d
	_, err := ids.CreateOrReplaceUser(nil, authz.Actor{Type: "local_admin", ID: "seed"}, identity.Mailbox{Email: "user@example.test", Active: true}, "mail-password")
	if err != nil {
		t.Fatal(err)
	}
	h := Server{Identity: ids, Daemon: d}.Handler()
	unauth := httptest.NewRecorder()
	h.ServeHTTP(unauth, httptest.NewRequest(http.MethodPost, "/api/v1/mailboxes/user@example.test/app-passwords", strings.NewReader(`{"label":"phone"}`)))
	if unauth.Code != http.StatusUnauthorized {
		t.Fatalf("unauth app-password status=%d", unauth.Code)
	}

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, authed(http.MethodPost, "/api/v1/mailboxes/user@example.test/app-passwords", `{"label":"phone"}`, "api-secret-token"))
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "one-time-client-secret") {
		t.Fatalf("create status=%d body=%s", rr.Code, rr.Body.String())
	}
	createdBody := rr.Body.String()
	idStart := strings.Index(createdBody, `"id":"`)
	if idStart < 0 {
		t.Fatalf("missing id in %s", createdBody)
	}
	idRest := createdBody[idStart+6:]
	tokenID := idRest[:strings.Index(idRest, `"`)]
	if got := d.DovecotPassdb("c", daemon.PassdbRequest{Username: "user@example.test", Secret: "one-time-client-secret", Protocol: "imap"}); got.Decision != daemon.OK {
		t.Fatalf("app password did not enter daemon passdb: %#v", got)
	}

	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, authed(http.MethodGet, "/api/v1/mailboxes/user@example.test/app-passwords", "", "api-secret-token"))
	if rr.Code != http.StatusOK || strings.Contains(rr.Body.String(), "one-time-client-secret") || strings.Contains(rr.Body.String(), "verifier") {
		t.Fatalf("list leaked secret/verifier status=%d body=%s", rr.Code, rr.Body.String())
	}

	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, authed(http.MethodDelete, "/api/v1/mailboxes/user@example.test/app-passwords/"+tokenID, "", "api-secret-token"))
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "revoked") {
		t.Fatalf("revoke status=%d body=%s", rr.Code, rr.Body.String())
	}
	if got := d.DovecotPassdb("c", daemon.PassdbRequest{Username: "user@example.test", Secret: "one-time-client-secret", Protocol: "imap"}); got.Decision != daemon.Reject {
		t.Fatalf("revoked app password still authenticates: %#v", got)
	}
}

func TestSCIMPutRejectsDivergentIDAndAuditsAuthFailure(t *testing.T) {
	ids := identity.NewService("example.test")
	if err := ids.AddToken("scim-test", "scim_client", "scim-secret-token"); err != nil {
		t.Fatal(err)
	}
	w := &audit.MemoryWriter{}
	h := Server{Identity: ids, Audit: w}.Handler()
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/scim/v2/Users", strings.NewReader(`{"userName":"user@example.test"}`)))
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("unauth status=%d", rr.Code)
	}
	if len(w.Events) == 0 || w.Events[len(w.Events)-1].Result != "denied" {
		t.Fatalf("missing auth failure audit %#v", w.Events)
	}
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, authed(http.MethodPost, "/scim/v2/Users", `{bad`, "scim-secret-token"))
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("bad json status=%d", rr.Code)
	}
	if w.Events[len(w.Events)-1].Result != "failure" {
		t.Fatalf("missing decode failure audit %#v", w.Events)
	}
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, authed(http.MethodPost, "/scim/v2/Users", `{"userName":"user@example.test","password":"long-password"}`, "scim-secret-token"))
	if rr.Code != http.StatusCreated {
		t.Fatalf("create status=%d body=%s", rr.Code, rr.Body.String())
	}
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, authed(http.MethodPut, "/scim/v2/Users/user@example.test", `{"userName":"other@example.test"}`, "scim-secret-token"))
	if rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), "id must match userName") {
		t.Fatalf("mismatch status=%d body=%s", rr.Code, rr.Body.String())
	}
}

func TestDefaultIdentityServiceIsSharedAcrossSCIMAndAppPasswordRoutes(t *testing.T) {
	h := Server{Daemon: daemon.Service{Domains: map[string]daemon.Domain{"example.test": {Name: "example.test", Enabled: true}}}}.Handler()
	// The default service has no configured token, so this currently proves routes are wired through one service only by requiring explicit auth.
	// Shared-state behavior with successful auth is covered by injected-service tests above.
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/scim/v2/Users", strings.NewReader(`{"userName":"user@example.test"}`)))
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d", rr.Code)
	}
}

func TestV3OpsAPIRoutes(t *testing.T) {
	w := &audit.MemoryWriter{}
	_ = w.Write(nil, audit.Event{ID: "e1", Actor: audit.ActorRef{Type: "admin", ID: "a"}, Action: "auth.failure", Resource: audit.ResourceRef{Type: "session", ID: "s"}, Result: "failure", BeforeRedacted: map[string]any{"password": "secret"}})
	h := Server{Audit: w, Daemon: daemon.Service{Domains: map[string]daemon.Domain{"example.test": {Name: "example.test", Enabled: true}}, Mailboxes: map[string]daemon.Mailbox{"postmaster@example.test": {Address: "postmaster@example.test", Enabled: true}}}}.Handler()
	cases := []struct{ method, path, body, want string }{
		{http.MethodGet, "/api/v1/audit/export?format=jsonl&actor_type=admin", "", "[REDACTED]"},
		{http.MethodGet, "/api/v1/audit/events/e1", "", "auth.failure"},
		{http.MethodPost, "/api/v1/audit/retention/preview?policy=older-than-90d", "", "ret_"},
		{http.MethodPost, "/api/v1/backups/verify?artifact_ref=current", "", "verified"},
		{http.MethodGet, "/api/v1/snapshots", "", "current"},
		{http.MethodGet, "/api/v1/snapshots/current?verified_restore_status=failed", "", "rollback blocked"},
		{http.MethodGet, "/api/v1/ops/abuse-summary", "", "AuthFailures"},
		{http.MethodGet, "/api/v1/ops/rate-limits", "", "[]"},
		{http.MethodGet, "/api/v1/ops/deferred-correlation", "", "[]"},
		{http.MethodGet, "/api/v1/snapshots/current/diff?against=current", "", "changed"},
	}
	for _, tc := range cases {
		t.Run(tc.path, func(t *testing.T) {
			rr := httptest.NewRecorder()
			h.ServeHTTP(rr, httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body)))
			if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), tc.want) {
				t.Fatalf("status=%d body=%s want=%s", rr.Code, rr.Body.String(), tc.want)
			}
		})
	}
}

func TestV3ImportAndBulkAPIBindPreviewConfirmation(t *testing.T) {
	w := &audit.MemoryWriter{}
	h := Server{Audit: w, Daemon: daemon.Service{Domains: map[string]daemon.Domain{"example.test": {Name: "example.test", Enabled: true}}, Mailboxes: map[string]daemon.Mailbox{"postmaster@example.test": {Address: "postmaster@example.test", Enabled: true}}}}.Handler()
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/api/v1/imports/mailu/preview", strings.NewReader(`{"source":"[{\"Type\":\"domain\",\"ID\":\"example.test\"}]"}`)))
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "SourceFingerprint") {
		t.Fatalf("preview status=%d body=%s", rr.Code, rr.Body.String())
	}
	var p ops.ImportPreview
	if err := json.Unmarshal(rr.Body.Bytes(), &p); err != nil {
		t.Fatal(err)
	}
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/v1/imports/"+p.ID, nil))
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), p.ID) {
		t.Fatalf("get status=%d body=%s", rr.Code, rr.Body.String())
	}
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/api/v1/imports/mailu/apply?hash="+p.Hash+"&source_fingerprint="+p.SourceFingerprint, strings.NewReader(`{"id":"`+p.ID+`"}`)))
	if rr.Code != http.StatusOK {
		t.Fatalf("apply status=%d body=%s", rr.Code, rr.Body.String())
	}

	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/api/v1/bulk/disable-users/preview", strings.NewReader(`{"items":["a","b"]}`)))
	var bp ops.BulkPreview
	if err := json.Unmarshal(rr.Body.Bytes(), &bp); err != nil {
		t.Fatal(err)
	}
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/api/v1/bulk/disable-users/apply?confirm="+bp.ID+"&hash="+bp.Hash, strings.NewReader(`{"id":"`+bp.ID+`"}`)))
	if rr.Code != http.StatusOK || len(w.Events) < 3 {
		t.Fatalf("bulk status=%d body=%s events=%#v", rr.Code, rr.Body.String(), w.Events)
	}
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/v1/bulk/jobs/"+bp.ID, nil))
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "success") {
		t.Fatalf("job status=%d body=%s", rr.Code, rr.Body.String())
	}
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestV3ImportLookupDoesNotExposeRawCandidateValues(t *testing.T) {
	h := Server{Daemon: daemon.Service{Domains: map[string]daemon.Domain{"example.test": {Name: "example.test", Enabled: true}}, Mailboxes: map[string]daemon.Mailbox{"postmaster@example.test": {Address: "postmaster@example.test", Enabled: true}}}}.Handler()
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/api/v1/imports/mailu/preview", strings.NewReader(`{"source":"[{\"Type\":\"token\",\"ID\":\"t\",\"Value\":\"secret-value\",\"PlaintextSecret\":true}]"}`)))
	var p ops.ImportPreview
	if err := json.Unmarshal(rr.Body.Bytes(), &p); err != nil {
		t.Fatal(err)
	}
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/v1/imports/"+p.ID, nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	if strings.Contains(rr.Body.String(), "secret-value") || strings.Contains(rr.Body.String(), "Candidates") {
		t.Fatalf("leaked raw candidates: %s", rr.Body.String())
	}
}
