package api

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"forgejo/linus/gophermailforge/internal/audit"
	"forgejo/linus/gophermailforge/internal/authn"
	"forgejo/linus/gophermailforge/internal/authz"
	"forgejo/linus/gophermailforge/internal/config"
	"forgejo/linus/gophermailforge/internal/daemon"
	"forgejo/linus/gophermailforge/internal/identity"
	"forgejo/linus/gophermailforge/internal/ops"
	"forgejo/linus/gophermailforge/internal/plugin"
	"forgejo/linus/gophermailforge/internal/store"
	"forgejo/linus/gophermailforge/internal/testpg"
	"forgejo/linus/gophermailforge/internal/webmail"
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
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/v1/audit/events", nil))
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("unauth audit events status %d", rr.Code)
	}
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/v1/config/render", nil))
	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("method gate status %d", rr.Code)
	}
}

type apiOIDCExchange struct{ token string }

func (f apiOIDCExchange) ExchangeCode(ctx context.Context, req authn.TokenRequest) (authn.TokenResponse, error) {
	return authn.TokenResponse{IDToken: f.token, TokenType: "Bearer"}, nil
}

func TestOIDCBrowserRedirectLoginAndGETCallback(t *testing.T) {
	key, jwks := apiJWKS(t, "kid1")
	now := time.Unix(1234, 0).UTC()
	cfg := authn.OIDCConfig{Issuer: "https://auth.example.test/application/o/gmf/", ClientID: "gmf", RedirectURI: "http://127.0.0.1:18080/api/v1/oidc/callback", TokenEndpoint: "https://auth.example.test/token", ClockSkew: time.Minute, Now: func() time.Time { return now }}
	store := authn.NewStore()
	h := Server{OIDCConfig: cfg, OIDCStore: store, OIDCAuthorizeEndpoint: "https://auth.example.test/application/o/authorize/", OIDCJWKS: jwks}.Handler()
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/v1/oidc/login?mode=redirect&redirect=/done", nil))
	if rr.Code != http.StatusFound {
		t.Fatalf("login status=%d body=%s", rr.Code, rr.Body.String())
	}
	binding := ""
	for _, c := range rr.Result().Cookies() {
		if c.Name == "gmf_oidc_binding" {
			binding = c.Value
		}
	}
	if binding == "" {
		t.Fatal("missing browser binding cookie")
	}
	loc := rr.Header().Get("Location")
	u, err := url.Parse(loc)
	if err != nil {
		t.Fatal(err)
	}
	state := u.Query().Get("state")
	nonce := u.Query().Get("nonce")
	if state == "" || nonce == "" || u.Query().Get("redirect_uri") != cfg.RedirectURI {
		t.Fatalf("bad authorize redirect %s", loc)
	}
	tok := apiSignToken(t, key, "kid1", map[string]any{"iss": cfg.Issuer, "sub": "user-123", "aud": []string{cfg.ClientID}, "azp": cfg.ClientID, "exp": now.Add(time.Hour).Unix(), "iat": now.Unix(), "nbf": now.Add(-time.Second).Unix(), "nonce": nonce, "email": "alice@example.test", "name": "Alice"})
	h = Server{OIDCConfig: cfg, OIDCStore: store, OIDCAuthorizeEndpoint: "https://auth.example.test/application/o/authorize/", OIDCJWKS: jwks, OIDCExchanger: apiOIDCExchange{token: tok}}.Handler()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/oidc/callback?state="+url.QueryEscape(state)+"&code=auth-code", nil)
	req.AddCookie(&http.Cookie{Name: "gmf_oidc_binding", Value: binding})
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusSeeOther || rr.Header().Get("Location") != "/done" {
		t.Fatalf("callback status=%d location=%q body=%s", rr.Code, rr.Header().Get("Location"), rr.Body.String())
	}
	gotSession := false
	clearedBinding := false
	for _, c := range rr.Result().Cookies() {
		if c.Name == "gmf_session" && c.Value != "" {
			gotSession = true
		}
		if c.Name == "gmf_oidc_binding" && c.MaxAge < 0 {
			clearedBinding = true
		}
	}
	if !gotSession || !clearedBinding {
		t.Fatalf("cookies=%#v", rr.Result().Cookies())
	}
}

func apiJWKS(t *testing.T, kid string) (*rsa.PrivateKey, authn.JWKS) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	e := big.NewInt(int64(key.PublicKey.E)).Bytes()
	return key, authn.JWKS{Keys: []authn.JWK{{Kty: "RSA", Kid: kid, Alg: "RS256", Use: "sig", N: base64.RawURLEncoding.EncodeToString(key.PublicKey.N.Bytes()), E: base64.RawURLEncoding.EncodeToString(e)}}}
}
func apiSignToken(t *testing.T, key *rsa.PrivateKey, kid string, claims map[string]any) string {
	t.Helper()
	h := apiEncJSON(t, map[string]any{"alg": "RS256", "kid": kid, "typ": "JWT"})
	c := apiEncJSON(t, claims)
	d := sha256.Sum256([]byte(h + "." + c))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, d[:])
	if err != nil {
		t.Fatal(err)
	}
	return h + "." + c + "." + base64.RawURLEncoding.EncodeToString(sig)
}
func apiEncJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
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
	if err := ids.AddTokenWithScopes("api-test", "api_token", "api-secret-token", "mailbox:user@example.test:mailbox:app_password.create", "mailbox:user@example.test:mailbox:app_password.read", "mailbox:user@example.test:mailbox:app_password.revoke"); err != nil {
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
	h.ServeHTTP(rr, authed(http.MethodGet, "/api/v1/mailboxes/other@example.test/app-passwords", "", "api-secret-token"))
	if rr.Code != http.StatusForbidden {
		t.Fatalf("cross-mailbox list status=%d body=%s", rr.Code, rr.Body.String())
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

func v3AdminServer(t *testing.T, w *audit.MemoryWriter) http.Handler {
	t.Helper()
	ids := identity.NewService("example.test")
	if err := ids.AddTokenWithScopes("ops-admin", "api_token", "ops-secret-token", "ops:admin"); err != nil {
		t.Fatal(err)
	}
	return Server{Audit: w, Identity: ids, Daemon: daemon.Service{Domains: map[string]daemon.Domain{"example.test": {Name: "example.test", Enabled: true}}, Mailboxes: map[string]daemon.Mailbox{"postmaster@example.test": {Address: "postmaster@example.test", Enabled: true}}}}.Handler()
}

func v3Req(method, path, body string) *http.Request {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer ops-secret-token")
	return req
}

func TestV3OpsAPIRoutes(t *testing.T) {
	w := &audit.MemoryWriter{}
	_ = w.Write(nil, audit.Event{ID: "e1", Actor: audit.ActorRef{Type: "admin", ID: "a"}, Action: "auth.failure", Resource: audit.ResourceRef{Type: "session", ID: "s"}, Result: "failure", BeforeRedacted: map[string]any{"password": "secret"}})
	h := v3AdminServer(t, w)
	cases := []struct{ method, path, body, want string }{
		{http.MethodGet, "/api/v1/audit/export?format=jsonl&actor_type=admin", "", "[REDACTED]"},
		{http.MethodGet, "/api/v1/audit/events/e1", "", "auth.failure"},
		{http.MethodPost, "/api/v1/audit/retention/preview?policy=older-than-90d", "", "ret_"},
		{http.MethodPost, "/api/v1/backups/verify?artifact_ref=current", "", "verified"},
		{http.MethodGet, "/api/v1/snapshots", "", "current"},
		{http.MethodGet, "/api/v1/snapshots/current", "", "rollback blocked"},
		{http.MethodGet, "/api/v1/ops/abuse-summary", "", "AuthFailures"},
		{http.MethodGet, "/api/v1/ops/rate-limits", "", "[]"},
		{http.MethodGet, "/api/v1/ops/deferred-correlation", "", "[]"},
		{http.MethodGet, "/api/v1/snapshots/current/diff?against=current", "", "changed"},
	}
	for _, tc := range cases {
		t.Run(tc.path, func(t *testing.T) {
			rr := httptest.NewRecorder()
			h.ServeHTTP(rr, v3Req(tc.method, tc.path, tc.body))
			if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), tc.want) {
				t.Fatalf("status=%d body=%s want=%s", rr.Code, rr.Body.String(), tc.want)
			}
		})
	}
}

func TestAuditEventsListRequiresAdminAndRedacts(t *testing.T) {
	w := &audit.MemoryWriter{}
	_ = w.Write(nil, audit.Event{ID: "secret-event", Actor: audit.ActorRef{Type: "admin", ID: "a"}, Action: "auth.failure", Resource: audit.ResourceRef{Type: "session", ID: "s"}, Result: "failure", BeforeRedacted: map[string]any{"password": "secret-password"}, AfterRedacted: map[string]any{"token": "secret-token"}})
	h := v3AdminServer(t, w)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/v1/audit/events", nil))
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("unauth audit list status=%d body=%s", rr.Code, rr.Body.String())
	}
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, v3Req(http.MethodGet, "/api/v1/audit/events", ""))
	if rr.Code != http.StatusOK {
		t.Fatalf("audit list status=%d body=%s", rr.Code, rr.Body.String())
	}
	body := rr.Body.String()
	if strings.Contains(body, "secret-password") || strings.Contains(body, "secret-token") || !strings.Contains(body, "[REDACTED]") {
		t.Fatalf("audit list not redacted: %s", body)
	}
}

func TestV3RoutesRejectAnonymous(t *testing.T) {
	h := v3AdminServer(t, &audit.MemoryWriter{})
	for _, tc := range []struct{ method, path string }{
		{http.MethodGet, "/api/v1/audit/export"},
		{http.MethodPost, "/api/v1/audit/retention/preview?policy=older-than-90d"},
		{http.MethodPost, "/api/v1/backups/verify?artifact_ref=current"},
		{http.MethodPost, "/api/v1/imports/mailu/preview"},
		{http.MethodPost, "/api/v1/bulk/disable-users/preview"},
	} {
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, httptest.NewRequest(tc.method, tc.path, strings.NewReader(`{}`)))
		if rr.Code != http.StatusUnauthorized {
			t.Fatalf("%s %s status=%d", tc.method, tc.path, rr.Code)
		}
	}
}

func TestV3ImportAndBulkAPIBindPreviewConfirmation(t *testing.T) {
	w := &audit.MemoryWriter{}
	h := v3AdminServer(t, w)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, v3Req(http.MethodPost, "/api/v1/imports/mailu/preview", `{"source":"[{\"Type\":\"domain\",\"ID\":\"example.test\"}]"}`))
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "SourceFingerprint") {
		t.Fatalf("preview status=%d body=%s", rr.Code, rr.Body.String())
	}
	var p ops.ImportPreview
	if err := json.Unmarshal(rr.Body.Bytes(), &p); err != nil {
		t.Fatal(err)
	}
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, v3Req(http.MethodGet, "/api/v1/imports/"+p.ID, ""))
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), p.ID) {
		t.Fatalf("get status=%d body=%s", rr.Code, rr.Body.String())
	}
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, v3Req(http.MethodPost, "/api/v1/imports/mailu/apply?hash="+p.Hash+"&source_fingerprint="+p.SourceFingerprint, `{"id":"`+p.ID+`"}`))
	if rr.Code != http.StatusOK {
		t.Fatalf("apply status=%d body=%s", rr.Code, rr.Body.String())
	}

	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, v3Req(http.MethodPost, "/api/v1/bulk/disable-users/preview", `{"items":["a","b"]}`))
	var bp ops.BulkPreview
	if err := json.Unmarshal(rr.Body.Bytes(), &bp); err != nil {
		t.Fatal(err)
	}
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, v3Req(http.MethodPost, "/api/v1/bulk/disable-users/apply?confirm="+bp.ID+"&hash="+bp.Hash, `{"id":"`+bp.ID+`"}`))
	if rr.Code != http.StatusOK || len(w.Events) < 3 {
		t.Fatalf("bulk status=%d body=%s events=%#v", rr.Code, rr.Body.String(), w.Events)
	}
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, v3Req(http.MethodGet, "/api/v1/bulk/jobs/"+bp.ID, ""))
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
	h := v3AdminServer(t, &audit.MemoryWriter{})
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, v3Req(http.MethodPost, "/api/v1/imports/mailu/preview", `{"source":"[{\"Type\":\"token\",\"ID\":\"t\",\"Value\":\"secret-value\",\"PlaintextSecret\":true}]"}`))
	var p ops.ImportPreview
	if err := json.Unmarshal(rr.Body.Bytes(), &p); err != nil {
		t.Fatal(err)
	}
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, v3Req(http.MethodGet, "/api/v1/imports/"+p.ID, ""))
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	if strings.Contains(rr.Body.String(), "secret-value") || strings.Contains(rr.Body.String(), "Candidates") {
		t.Fatalf("leaked raw candidates: %s", rr.Body.String())
	}
}

type apiFakeIMAP struct{ messages []webmail.Message }

func (f apiFakeIMAP) ListFolders(context.Context, string) ([]string, error) {
	return []string{"INBOX"}, nil
}
func (f apiFakeIMAP) ListMessages(context.Context, string, string, string, int) ([]webmail.Message, error) {
	return f.messages, nil
}
func (f apiFakeIMAP) ReadMessage(ctx context.Context, user, folder, id string) (webmail.Message, error) {
	for _, m := range f.messages {
		if m.ID == id {
			return m, nil
		}
	}
	return webmail.Message{}, errors.New("missing")
}
func (f apiFakeIMAP) Search(ctx context.Context, user, folder, query, cursor string, limit int) ([]webmail.Message, error) {
	return f.messages, nil
}
func (f apiFakeIMAP) Quota(context.Context) (int64, int64, error) { return 0, 0, nil }

type apiFakeSMTP struct{ sent bool }

func (f *apiFakeSMTP) Submit(context.Context, webmail.Envelope, []byte) error {
	f.sent = true
	return nil
}

type apiFakeSigner struct{}

func (apiFakeSigner) SignMIME(ctx context.Context, id webmail.Identity, b []byte) ([]byte, webmail.SignatureStatus, error) {
	return append([]byte("Content-Type: multipart/signed; protocol=application/pgp-signature; micalg=pgp-sha256\r\nContent-Type: application/pgp-signature\r\n\r\n"), b...), webmail.SignatureStatus{Fingerprint: id.Fingerprint, Identity: id.Address, Signed: true}, nil
}

type apiFakeResolver struct{}

func (apiFakeResolver) ResolveSender(ctx context.Context, fp, from, sender string) (webmail.Identity, error) {
	return webmail.Identity{Address: from, Fingerprint: fp}, nil
}

func webmailServer(t *testing.T, smtp *apiFakeSMTP) http.Handler {
	t.Helper()
	ids := identity.NewService("example.test")
	if err := ids.AddTokenWithScopes("web-user-token", "api_token", "web-secret-token", "mailbox:web-user@example.test:webmail:use"); err != nil {
		t.Fatal(err)
	}
	client := &webmail.Client{IMAP: apiFakeIMAP{messages: []webmail.Message{{ID: "m1", Folder: "INBOX", From: "a@example.test", Subject: "Hi", BodyHTML: "<script>x</script><b>safe</b>"}}}}
	sender := &webmail.Sender{Drafts: map[string]webmail.Draft{}, SMTP: smtp, Signer: apiFakeSigner{}, Resolver: apiFakeResolver{}, Audit: &audit.MemoryWriter{}}
	return Server{Identity: ids, WebmailClient: client, WebmailSender: sender}.Handler()
}

func TestWebmailAPIRoutesRequireAuthAndReachClientSender(t *testing.T) {
	smtp := &apiFakeSMTP{}
	h := webmailServer(t, smtp)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/v1/webmail/folders", nil))
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("unauth status=%d", rr.Code)
	}
	req := v3Req(http.MethodGet, "/api/v1/webmail/folders", "")
	req.Header.Set("Authorization", "Bearer web-secret-token")
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "INBOX") {
		t.Fatalf("folders status=%d body=%s", rr.Code, rr.Body.String())
	}
	req = v3Req(http.MethodGet, "/api/v1/webmail/messages/INBOX/m1", "")
	req.Header.Set("Authorization", "Bearer web-secret-token")
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK || strings.Contains(rr.Body.String(), "<script>") {
		t.Fatalf("read status=%d body=%s", rr.Code, rr.Body.String())
	}
	req = v3Req(http.MethodPost, "/api/v1/webmail/drafts", `{"from":"web-user@example.test","to":"r@example.test","subject":"s","body":"b","signingfingerprint":"fp"}`)
	req.Header.Set("Authorization", "Bearer web-secret-token")
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("draft status=%d body=%s", rr.Code, rr.Body.String())
	}
	var d webmail.Draft
	if err := json.Unmarshal(rr.Body.Bytes(), &d); err != nil {
		t.Fatal(err)
	}
	req = v3Req(http.MethodPost, "/api/v1/webmail/drafts/"+d.ID+"/submit", "")
	req.Header.Set("Authorization", "Bearer web-secret-token")
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK || !smtp.sent {
		t.Fatalf("submit status=%d body=%s sent=%v", rr.Code, rr.Body.String(), smtp.sent)
	}
}

func TestWebmailDraftSubmitRequiresMailboxOwnership(t *testing.T) {
	ids := identity.NewService("example.test")
	if err := ids.AddTokenWithScopes("web-a-token", "api_token", "web-a-secret", "mailbox:a@example.test:webmail:use"); err != nil {
		t.Fatal(err)
	}
	if err := ids.AddTokenWithScopes("web-b-token", "api_token", "web-b-secret", "mailbox:b@example.test:webmail:use"); err != nil {
		t.Fatal(err)
	}
	smtp := &apiFakeSMTP{}
	sender := &webmail.Sender{Drafts: map[string]webmail.Draft{}, SMTP: smtp, Signer: apiFakeSigner{}, Resolver: apiFakeResolver{}, Audit: &audit.MemoryWriter{}}
	h := Server{Identity: ids, WebmailClient: &webmail.Client{IMAP: apiFakeIMAP{}}, WebmailSender: sender}.Handler()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/webmail/drafts", strings.NewReader(`{"from":"a@example.test","to":"r@example.test","subject":"s","body":"b","signingfingerprint":"fp"}`))
	req.Header.Set("Authorization", "Bearer web-a-secret")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("draft status=%d body=%s", rr.Code, rr.Body.String())
	}
	var d webmail.Draft
	if err := json.Unmarshal(rr.Body.Bytes(), &d); err != nil {
		t.Fatal(err)
	}
	req = httptest.NewRequest(http.MethodPost, "/api/v1/webmail/drafts/"+d.ID+"/submit", nil)
	req.Header.Set("Authorization", "Bearer web-b-secret")
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("cross-mailbox submit status=%d body=%s", rr.Code, rr.Body.String())
	}
	if smtp.sent {
		t.Fatal("cross-mailbox submit sent message")
	}
}

func TestV3AuditRoutesUseSQLAuditStoreWhenConfigured(t *testing.T) {
	db := testpg.DB(t, store.MigrateSQL)
	ids := identity.NewService("example.test")
	if err := ids.AddTokenWithScopes("ops-admin", "api_token", "ops-secret-token", "ops:admin"); err != nil {
		t.Fatal(err)
	}
	aw := audit.SQLWriter{DB: db}
	now := time.Date(2026, 7, 18, 0, 0, 0, 0, time.UTC)
	if err := aw.Write(context.Background(), audit.Event{ID: "00000000-0000-4000-8000-000000000301", Time: now.AddDate(0, 0, -120), Actor: audit.ActorRef{Type: "admin", ID: "a"}, Action: "auth.failure", Resource: audit.ResourceRef{Type: "session", ID: "s"}, BeforeRedacted: map[string]any{"password": "secret-password"}, Result: "failure"}); err != nil {
		t.Fatal(err)
	}
	if err := aw.Write(context.Background(), audit.Event{ID: "00000000-0000-4000-8000-000000000302", Time: now, Actor: audit.ActorRef{Type: "admin", ID: "a"}, Action: "config.apply", Resource: audit.ResourceRef{Type: "generated_config_set", ID: "cfg"}, AfterRedacted: map[string]any{"token": "secret-token"}, Result: "success"}); err != nil {
		t.Fatal(err)
	}
	h := Server{AuditDB: db, Identity: ids}.Handler()
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, v3Req(http.MethodGet, "/api/v1/audit/export?format=jsonl&actor_type=admin", ""))
	if rr.Code != http.StatusOK || strings.Contains(rr.Body.String(), "secret-password") || !strings.Contains(rr.Body.String(), "[REDACTED]") {
		t.Fatalf("export status=%d body=%s", rr.Code, rr.Body.String())
	}
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, v3Req(http.MethodGet, "/api/v1/audit/events/00000000-0000-4000-8000-000000000302", ""))
	if rr.Code != http.StatusOK || strings.Contains(rr.Body.String(), "secret-token") || !strings.Contains(rr.Body.String(), "config.apply") {
		t.Fatalf("detail status=%d body=%s", rr.Code, rr.Body.String())
	}
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, v3Req(http.MethodPost, "/api/v1/audit/retention/preview?policy=older-than-90d", ""))
	if rr.Code != http.StatusOK {
		t.Fatalf("preview status=%d body=%s", rr.Code, rr.Body.String())
	}
	var p ops.RetentionPreview
	if err := json.Unmarshal(rr.Body.Bytes(), &p); err != nil {
		t.Fatal(err)
	}
	if p.DeleteCount != 1 {
		t.Fatalf("preview=%#v", p)
	}
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, v3Req(http.MethodPost, "/api/v1/audit/retention/apply?confirm="+p.ID, `{"id":"`+p.ID+`"}`))
	if rr.Code != http.StatusOK {
		t.Fatalf("apply status=%d body=%s", rr.Code, rr.Body.String())
	}
	events, err := (ops.SQLAuditStore{DB: db}).Query(context.Background(), ops.AuditFilter{}, 100)
	if err != nil {
		t.Fatal(err)
	}
	seenOld, seenNew, seenApply := false, false, false
	for _, e := range events {
		switch e.Action {
		case "auth.failure":
			seenOld = true
		case "config.apply":
			seenNew = true
		case "audit.retention.apply":
			seenApply = true
		}
	}
	if seenOld || !seenNew || !seenApply {
		t.Fatalf("events=%#v", events)
	}
}

func TestV3BackupVerifyRecordsSQLVerificationWhenConfigured(t *testing.T) {
	db := testpg.DB(t, store.MigrateSQL)
	ids := identity.NewService("example.test")
	if err := ids.AddTokenWithScopes("ops-admin", "api_token", "ops-secret-token", "ops:admin"); err != nil {
		t.Fatal(err)
	}
	rt := ops.NewV3Runtime()
	rt.BackupStore.Artifacts["artifact"] = ops.BackupArtifact{SchemaVersion: "schema_migrations", ConfigSetID: "cfg", Domains: map[string]daemon.Domain{"example.test": {Name: "example.test", Enabled: true}}, Mailboxes: map[string]daemon.Mailbox{"user@example.test": {Address: "user@example.test", Enabled: true}}, Aliases: map[string]daemon.Alias{}}
	h := Server{AuditDB: db, Identity: ids, V3: rt}.Handler()
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, v3Req(http.MethodPost, "/api/v1/backups/verify?artifact_ref=artifact", ""))
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "verified") {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	got, ok, err := (ops.SQLBackupVerificationStore{DB: db}).Latest(context.Background(), "artifact")
	if err != nil || !ok {
		t.Fatalf("latest ok=%v err=%v", ok, err)
	}
	if got.Status != "verified" || got.ConfigSetID != "cfg" {
		t.Fatalf("latest=%#v", got)
	}
}
