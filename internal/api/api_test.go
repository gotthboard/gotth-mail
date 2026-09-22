package api

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"forgejo/gotthboard/gotth-mail/internal/audit"
	"forgejo/gotthboard/gotth-mail/internal/authn"
	"forgejo/gotthboard/gotth-mail/internal/authz"
	"forgejo/gotthboard/gotth-mail/internal/config"
	"forgejo/gotthboard/gotth-mail/internal/daemon"
	"forgejo/gotthboard/gotth-mail/internal/identity"
	"forgejo/gotthboard/gotth-mail/internal/notification"
	"forgejo/gotthboard/gotth-mail/internal/ops"
	"forgejo/gotthboard/gotth-mail/internal/outboundpolicy"
	"forgejo/gotthboard/gotth-mail/internal/plugin"
	"forgejo/gotthboard/gotth-mail/internal/store"
	"forgejo/gotthboard/gotth-mail/internal/testpg"
	"forgejo/gotthboard/gotth-mail/internal/webmail"
	gotthoidc "github.com/gotthboard/gotth-oidc/pkg/oidc"
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
  oidc_client_id: "gotth-mail"
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
	h := Server{Authz: authz.StaticAuthorizer{}, Config: cfg, Plugins: plugin.Registry{Plugins: map[string]plugin.Registration{"stub-dns": {Name: "stub-dns", Enabled: true, ServiceToken: "tok", Capabilities: []string{"dns.lookup"}}}}, PluginHealth: func(context.Context, string) (plugin.HealthResponse, error) {
		return plugin.HealthResponse{Healthy: true}, nil
	}, Daemon: daemon.Service{Domains: map[string]daemon.Domain{"example.test": {Name: "example.test", Enabled: true}}, Mailboxes: map[string]daemon.Mailbox{"postmaster@example.test": {Address: "postmaster@example.test", Enabled: true}}}, Queue: &ops.Queue{Summary: ops.QueueSummary{Active: 1, Deferred: []string{"abc"}}}}.Handler()
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

func TestPluginStatusNeverSerializesServiceCredential(t *testing.T) {
	handler := Server{Plugins: plugin.Registry{Plugins: map[string]plugin.Registration{"notify": {Name: "notify", Seam: plugin.Notification, Endpoint: "notification-plugin:9443", Enabled: true, ServiceToken: "credential-must-not-leak", Capabilities: []string{"notification.alert.send"}}}}}.Handler()
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/v1/plugins", nil))
	if rr.Code != http.StatusOK || strings.Contains(rr.Body.String(), "credential-must-not-leak") || strings.Contains(rr.Body.String(), "service_token") {
		t.Fatalf("unsafe plugin status response status=%d body=%q", rr.Code, rr.Body.String())
	}
}

func TestPluginHealthFailsClosedWithoutLeakingProbeErrors(t *testing.T) {
	registration := plugin.Registration{Name: "notify", Seam: plugin.Notification, Enabled: true, ServiceToken: "credential-must-not-leak"}
	for _, tc := range []struct {
		name   string
		lookup func(context.Context, string) (plugin.HealthResponse, error)
	}{
		{name: "missing probe"},
		{name: "failed probe", lookup: func(context.Context, string) (plugin.HealthResponse, error) {
			return plugin.HealthResponse{}, errors.New("upstream secret diagnostic")
		}},
		{name: "unhealthy probe", lookup: func(context.Context, string) (plugin.HealthResponse, error) {
			return plugin.HealthResponse{Healthy: false, Message: "private backend detail"}, nil
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := Server{Plugins: plugin.Registry{Plugins: map[string]plugin.Registration{"notify": registration}}, PluginHealth: tc.lookup}.Handler()
			rr := httptest.NewRecorder()
			h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/v1/plugins/notify/health", nil))
			if rr.Code != http.StatusServiceUnavailable || !strings.Contains(rr.Body.String(), `"healthy":false`) {
				t.Fatalf("plugin health response = %d %s", rr.Code, rr.Body.String())
			}
			for _, forbidden := range []string{"credential-must-not-leak", "upstream secret diagnostic", "private backend detail"} {
				if strings.Contains(rr.Body.String(), forbidden) {
					t.Fatalf("plugin health leaked %q in %q", forbidden, rr.Body.String())
				}
			}
		})
	}
}

func TestStatusReportsReleaseIdentity(t *testing.T) {
	t.Parallel()
	h := (Server{}).Handler()
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/v1/status", nil))
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), `"status":"development"`) || !strings.Contains(rr.Body.String(), `"version":"dev"`) || !strings.Contains(rr.Body.String(), `"mail_stack_complete":false`) {
		t.Fatalf("status response = %d %s", rr.Code, rr.Body.String())
	}
}

type apiOIDCClient struct {
	authorization gotthoidc.Authorization
	identity      gotthoidc.Identity
}

func (client *apiOIDCClient) Begin() (gotthoidc.Authorization, error) {
	return client.authorization, nil
}

func (client *apiOIDCClient) CompleteResponse(_ context.Context, response gotthoidc.AuthorizationResponse, attempt gotthoidc.ProtectedAttempt) (gotthoidc.Identity, error) {
	if response.State == "" || response.Code == "" || attempt != client.authorization.Attempt {
		return gotthoidc.Identity{}, errors.New("bad completion input")
	}
	return client.identity, nil
}

func TestOIDCBrowserRedirectLoginAndGETCallback(t *testing.T) {
	now := time.Unix(1234, 0).UTC()
	redirectURI := "http://127.0.0.1:18080/api/v1/oidc/callback"
	state, nonce := "api-state", "api-nonce"
	attempt := gotthoidc.ProtectedAttempt{StateHash: sha256.Sum256([]byte(state)), ContextCiphertext: "protected-context"}
	attempt.NonceCiphertext[0] = 1
	attempt.PKCEVerifierCiphertext[0] = 2
	client := &apiOIDCClient{authorization: gotthoidc.Authorization{URL: "https://auth.example.test/application/o/authorize/?state=" + state + "&nonce=" + nonce + "&code_challenge=challenge&code_challenge_method=S256", Attempt: attempt}}
	store := authn.NewStore()
	h := Server{OIDCClient: client, OIDCStore: store, OIDCRedirectURI: redirectURI, OIDCNow: func() time.Time { return now }}.Handler()
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/v1/oidc/login?mode=redirect&redirect=/done", nil))
	if rr.Code != http.StatusFound {
		t.Fatalf("login status=%d body=%s", rr.Code, rr.Body.String())
	}
	binding := ""
	for _, c := range rr.Result().Cookies() {
		if c.Name == "gotth_mail_oidc_binding" {
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
	state = u.Query().Get("state")
	nonce = u.Query().Get("nonce")
	if state == "" || nonce == "" || u.Query().Get("code_challenge_method") != "S256" {
		t.Fatalf("bad authorize redirect %s", loc)
	}
	email := "alice@example.test"
	client.identity = gotthoidc.Identity{Issuer: "https://auth.example.test/application/o/gotth-mail/", Subject: "user-123", DisplayName: "Alice", Email: &email}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/oidc/callback?state="+url.QueryEscape(state)+"&code=auth-code", nil)
	req.AddCookie(&http.Cookie{Name: "gotth_mail_oidc_binding", Value: binding})
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusSeeOther || rr.Header().Get("Location") != "/done" {
		t.Fatalf("callback status=%d location=%q body=%s", rr.Code, rr.Header().Get("Location"), rr.Body.String())
	}
	gotSession := false
	clearedBinding := false
	for _, c := range rr.Result().Cookies() {
		if c.Name == "gotth_mail_session" && c.Value != "" {
			gotSession = true
		}
		if c.Name == "gotth_mail_oidc_binding" && c.MaxAge < 0 {
			clearedBinding = true
		}
	}
	if !gotSession || !clearedBinding {
		t.Fatalf("cookies=%#v", rr.Result().Cookies())
	}
}

func TestBoundOIDCSessionManagesOnlyOwnAppPasswordsWithCSRF(t *testing.T) {
	db, ids, _, scimHTTP := scimTestHandler(t, nil)
	create := authed(http.MethodPost, "/scim/v2/Users", `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"externalId":"bound-subject","userName":"member@example.test","active":true}`, "scim-secret-token")
	rr := httptest.NewRecorder()
	scimHTTP.ServeHTTP(rr, create)
	if rr.Code != http.StatusCreated {
		t.Fatalf("SCIM create status=%d body=%s", rr.Code, rr.Body.String())
	}
	userID := responseID(t, rr.Body.String())
	now := time.Unix(1700, 0).UTC()
	state := "bound-state"
	attempt := gotthoidc.ProtectedAttempt{StateHash: sha256.Sum256([]byte(state)), ContextCiphertext: "protected-context"}
	attempt.NonceCiphertext[0] = 1
	attempt.PKCEVerifierCiphertext[0] = 2
	email := "member@example.test"
	client := &apiOIDCClient{
		authorization: gotthoidc.Authorization{URL: "https://auth.example.test/application/o/authorize/?state=" + state + "&nonce=nonce&code_challenge=challenge&code_challenge_method=S256", Attempt: attempt},
		identity:      gotthoidc.Identity{Issuer: "https://auth.example.test/application/o/gotth-mail/", Subject: "bound-subject", Email: &email},
	}
	webmailSMTP := &apiFakeSMTP{}
	server := Server{
		OIDCClient: client, OIDCStore: authn.SQLStore{DB: db}, OIDCRedirectURI: "http://127.0.0.1:18080/api/v1/oidc/callback", OIDCNow: func() time.Time { return now }, Identity: ids, Authz: authz.StaticAuthorizer{},
		WebmailClient: &webmail.Client{IMAP: apiFakeIMAP{messages: []webmail.Message{{ID: "1", Folder: "INBOX", From: "sender@example.test", Subject: "session mail"}}}},
		WebmailSender: &webmail.Sender{Drafts: map[string]webmail.Draft{}, SMTP: webmailSMTP, Signer: apiFakeSigner{}, Resolver: apiFakeResolver{}, Policy: apiFakeOutboundPolicy{}, Audit: &audit.MemoryWriter{}},
	}
	h := server.Handler()
	login := httptest.NewRecorder()
	h.ServeHTTP(login, httptest.NewRequest(http.MethodGet, "/api/v1/oidc/login?mode=redirect", nil))
	var binding *http.Cookie
	for _, cookie := range login.Result().Cookies() {
		if cookie.Name == "gotth_mail_oidc_binding" {
			binding = cookie
		}
	}
	if login.Code != http.StatusFound || binding == nil {
		t.Fatalf("login status=%d cookies=%#v", login.Code, login.Result().Cookies())
	}
	callbackRequest := httptest.NewRequest(http.MethodGet, "/api/v1/oidc/callback?state="+state+"&code=code", nil)
	callbackRequest.AddCookie(binding)
	callback := httptest.NewRecorder()
	h.ServeHTTP(callback, callbackRequest)
	var sessionCookie, csrfCookie *http.Cookie
	for _, cookie := range callback.Result().Cookies() {
		switch cookie.Name {
		case "gotth_mail_session":
			sessionCookie = cookie
		case "gotth_mail_csrf":
			csrfCookie = cookie
		}
	}
	if callback.Code != http.StatusSeeOther || sessionCookie == nil || csrfCookie == nil || csrfCookie.HttpOnly {
		t.Fatalf("callback status=%d cookies=%#v body=%s", callback.Code, callback.Result().Cookies(), callback.Body.String())
	}
	for _, secret := range []string{sessionCookie.Value, csrfCookie.Value} {
		if strings.Contains(callback.Body.String(), secret) {
			t.Fatalf("callback disclosed cookie secret %q", secret)
		}
	}
	webmailIdentityRequest := httptest.NewRequest(http.MethodGet, "/api/v1/webmail/identity", nil)
	webmailIdentityRequest.AddCookie(sessionCookie)
	webmailIdentity := httptest.NewRecorder()
	h.ServeHTTP(webmailIdentity, webmailIdentityRequest)
	if webmailIdentity.Code != http.StatusOK || !strings.Contains(webmailIdentity.Body.String(), `"mailbox":"member@example.test"`) {
		t.Fatalf("session webmail identity status=%d body=%s", webmailIdentity.Code, webmailIdentity.Body.String())
	}
	webmailDraftRequest := httptest.NewRequest(http.MethodPost, "/api/v1/webmail/drafts", strings.NewReader(`{"to":"recipient@example.test","subject":"session draft","body":"body"}`))
	webmailDraftRequest.AddCookie(sessionCookie)
	webmailDraftRequest.AddCookie(csrfCookie)
	missingWebmailCSRF := httptest.NewRecorder()
	h.ServeHTTP(missingWebmailCSRF, webmailDraftRequest)
	if missingWebmailCSRF.Code != http.StatusForbidden {
		t.Fatalf("missing webmail CSRF status=%d body=%s", missingWebmailCSRF.Code, missingWebmailCSRF.Body.String())
	}
	webmailDraftRequest = httptest.NewRequest(http.MethodPost, "/api/v1/webmail/drafts", strings.NewReader(`{"to":"recipient@example.test","subject":"session draft","body":"body"}`))
	webmailDraftRequest.AddCookie(sessionCookie)
	webmailDraftRequest.AddCookie(csrfCookie)
	webmailDraftRequest.Header.Set("X-CSRF-Token", csrfCookie.Value)
	webmailDraft := httptest.NewRecorder()
	h.ServeHTTP(webmailDraft, webmailDraftRequest)
	if webmailDraft.Code != http.StatusOK || !strings.Contains(webmailDraft.Body.String(), `"SigningFingerprint":"fp"`) {
		t.Fatalf("session webmail draft status=%d body=%s", webmailDraft.Code, webmailDraft.Body.String())
	}
	webmailActionRequest := httptest.NewRequest(http.MethodPost, "/api/v1/webmail/message?folder=INBOX&id=1", strings.NewReader(`{"action":"mark_read"}`))
	webmailActionRequest.AddCookie(sessionCookie)
	webmailActionRequest.AddCookie(csrfCookie)
	webmailActionRequest.Header.Set("X-CSRF-Token", csrfCookie.Value)
	webmailAction := httptest.NewRecorder()
	h.ServeHTTP(webmailAction, webmailActionRequest)
	if webmailAction.Code != http.StatusOK {
		t.Fatalf("session webmail action status=%d body=%s", webmailAction.Code, webmailAction.Body.String())
	}

	request := httptest.NewRequest(http.MethodPost, "/api/v1/mailboxes/member@example.test/app-passwords", strings.NewReader(`{"label":"phone"}`))
	request.AddCookie(sessionCookie)
	missingCSRF := httptest.NewRecorder()
	h.ServeHTTP(missingCSRF, request)
	if missingCSRF.Code != http.StatusForbidden {
		t.Fatalf("missing CSRF status=%d body=%s", missingCSRF.Code, missingCSRF.Body.String())
	}
	request = httptest.NewRequest(http.MethodPost, "/api/v1/mailboxes/member@example.test/app-passwords", strings.NewReader(`{"label":"phone"}`))
	request.AddCookie(sessionCookie)
	request.AddCookie(csrfCookie)
	request.Header.Set("X-CSRF-Token", csrfCookie.Value)
	created := httptest.NewRecorder()
	h.ServeHTTP(created, request)
	if created.Code != http.StatusOK || !strings.Contains(created.Body.String(), `"secret_once"`) {
		t.Fatalf("create status=%d body=%s", created.Code, created.Body.String())
	}

	request = httptest.NewRequest(http.MethodGet, "/api/v1/mailboxes/other@example.test/app-passwords", nil)
	request.AddCookie(sessionCookie)
	crossMailbox := httptest.NewRecorder()
	h.ServeHTTP(crossMailbox, request)
	if crossMailbox.Code != http.StatusForbidden {
		t.Fatalf("cross-mailbox status=%d body=%s", crossMailbox.Code, crossMailbox.Body.String())
	}
	reassign := authed(http.MethodPut, "/scim/v2/Users/"+userID, `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"externalId":"other-subject","userName":"member@example.test","active":true}`, "scim-secret-token")
	reassigned := httptest.NewRecorder()
	scimHTTP.ServeHTTP(reassigned, reassign)
	if reassigned.Code != http.StatusConflict {
		t.Fatalf("bound externalId reassignment status=%d body=%s", reassigned.Code, reassigned.Body.String())
	}

	disable := authed(http.MethodPatch, "/scim/v2/Users/"+userID, `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","path":"active","value":false}]}`, "scim-secret-token")
	disabled := httptest.NewRecorder()
	scimHTTP.ServeHTTP(disabled, disable)
	if disabled.Code != http.StatusOK {
		t.Fatalf("disable status=%d body=%s", disabled.Code, disabled.Body.String())
	}
	request = httptest.NewRequest(http.MethodGet, "/api/v1/mailboxes/member@example.test/app-passwords", nil)
	request.AddCookie(sessionCookie)
	afterDisable := httptest.NewRecorder()
	h.ServeHTTP(afterDisable, request)
	if afterDisable.Code != http.StatusUnauthorized {
		t.Fatalf("disabled mailbox retained session authority: status=%d body=%s", afterDisable.Code, afterDisable.Body.String())
	}
	var revoked sql.NullTime
	if err := db.QueryRow(`SELECT revoked_at FROM sessions WHERE id=$1`, sessionCookie.Value).Scan(&revoked); err != nil || !revoked.Valid {
		t.Fatalf("session revoked_at=%#v err=%v", revoked, err)
	}
	reenable := authed(http.MethodPatch, "/scim/v2/Users/"+userID, `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","path":"active","value":true}]}`, "scim-secret-token")
	reenabled := httptest.NewRecorder()
	scimHTTP.ServeHTTP(reenabled, reenable)
	if reenabled.Code != http.StatusOK {
		t.Fatalf("re-enable status=%d body=%s", reenabled.Code, reenabled.Body.String())
	}
	request = httptest.NewRequest(http.MethodGet, "/api/v1/mailboxes/member@example.test/app-passwords", nil)
	request.AddCookie(sessionCookie)
	afterReenable := httptest.NewRecorder()
	h.ServeHTTP(afterReenable, request)
	if afterReenable.Code != http.StatusUnauthorized {
		t.Fatalf("SCIM re-enable revived revoked session: status=%d body=%s", afterReenable.Code, afterReenable.Body.String())
	}
}

func TestOIDCLoginRouteRequiresBrowserBinding(t *testing.T) {
	h := Server{OIDCClient: &apiOIDCClient{}}.Handler()
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
	if strings.HasPrefix(path, "/scim/v2/") && body != "" {
		req.Header.Set("Content-Type", "application/scim+json")
	}
	return req
}

func scimTestHandler(t *testing.T, writer audit.Writer) (*sql.DB, *identity.Service, *daemon.Service, http.Handler) {
	t.Helper()
	db := testpg.DB(t, store.MigrateSQL)
	ids, err := identity.NewSQLService(context.Background(), db, "example.test")
	if err != nil {
		t.Fatal(err)
	}
	if err := ids.AddToken("scim-test", "scim_client", "scim-secret-token"); err != nil {
		t.Fatal(err)
	}
	d := &daemon.Service{}
	ids.Daemon = d
	if writer == nil {
		writer = audit.SQLWriter{DB: db}
	}
	scimHandler, err := NewSCIMHandler("https://mail.example.test/scim/v2", db, ids, authz.StaticAuthorizer{}, writer)
	if err != nil {
		t.Fatal(err)
	}
	return db, ids, d, Server{Identity: ids, Daemon: *d, SCIM: scimHandler}.Handler()
}

func responseID(t *testing.T, body string) string {
	t.Helper()
	var response map[string]any
	if err := json.Unmarshal([]byte(body), &response); err != nil {
		t.Fatal(err)
	}
	id, _ := response["id"].(string)
	if id == "" {
		t.Fatalf("response has no opaque id: %s", body)
	}
	return id
}

func TestSCIMUserCreateUsesExistingDomainID(t *testing.T) {
	db, _, _, handler := scimTestHandler(t, nil)
	const existingDomainID = "20000000-0000-4000-8000-000000000001"
	if _, err := db.Exec(`INSERT INTO domains(id,name,enabled,created_at,updated_at) VALUES ($1,'example.test',true,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)`, existingDomainID); err != nil {
		t.Fatal(err)
	}

	response := httptest.NewRecorder()
	handler.ServeHTTP(response, authed(http.MethodPost, "/scim/v2/Users", `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"externalId":"existing-domain-subject","userName":"member@example.test","active":true}`, "scim-secret-token"))
	if response.Code != http.StatusCreated {
		t.Fatalf("create status=%d body=%s", response.Code, response.Body.String())
	}

	var domainID string
	if err := db.QueryRow(`SELECT domain_id::text FROM mailboxes WHERE scim_resource_id=$1`, responseID(t, response.Body.String())).Scan(&domainID); err != nil {
		t.Fatal(err)
	}
	if domainID != existingDomainID {
		t.Fatalf("mailbox domain_id=%q want existing %q", domainID, existingDomainID)
	}
}

func TestSCIMUsersSuccessAndFailurePaths(t *testing.T) {
	db, _, d, h := scimTestHandler(t, nil)

	unauth := httptest.NewRecorder()
	h.ServeHTTP(unauth, httptest.NewRequest(http.MethodPost, "/scim/v2/Users", strings.NewReader(`{"userName":"user@example.test"}`)))
	if unauth.Code != http.StatusUnauthorized {
		t.Fatalf("unauth SCIM status=%d", unauth.Code)
	}

	create := authed(http.MethodPost, "/scim/v2/Users", `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"externalId":"authentik-subject-1","userName":"user@example.test","displayName":"User","active":true,"password":"long-password"}`, "scim-secret-token")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, create)
	if rr.Code != http.StatusCreated || !strings.Contains(rr.Body.String(), "user@example.test") {
		t.Fatalf("create status=%d body=%s", rr.Code, rr.Body.String())
	}
	userID := responseID(t, rr.Body.String())
	if userID == "user@example.test" {
		t.Fatal("SCIM resource ID reused the mailbox address")
	}
	var storedDocument []byte
	var storedVerifier string
	var auditBefore, auditAfter sql.NullString
	if err := db.QueryRow(`SELECT data FROM scim_resources WHERE id=$1`, userID).Scan(&storedDocument); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT COALESCE(m.verifier,'') FROM mailboxes m WHERE m.scim_resource_id=$1`, userID).Scan(&storedVerifier); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT before_redacted_json, after_redacted_json FROM audit_events WHERE action='scim.user.create' AND resource_id=$1`, userID).Scan(&auditBefore, &auditAfter); err != nil {
		t.Fatal(err)
	}
	for label, value := range map[string]string{"resource": string(storedDocument), "audit_before": auditBefore.String, "audit_after": auditAfter.String} {
		if strings.Contains(value, "long-password") || strings.Contains(value, `"password"`) {
			t.Fatalf("%s retained SCIM password material: %s", label, value)
		}
	}
	if strings.Contains(storedVerifier, "long-password") || !strings.HasPrefix(storedVerifier, "pbkdf2_sha256$") {
		t.Fatalf("mailbox verifier is not an encoded one-way value: %q", storedVerifier)
	}
	if got := d.DovecotPassdb("c", daemon.PassdbRequest{Username: "user@example.test", Secret: "long-password", Protocol: "imap"}); got.Decision != daemon.OK {
		t.Fatalf("SCIM password did not enter daemon passdb: %#v", got)
	}

	patch := authed(http.MethodPatch, "/scim/v2/Users/"+userID, `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","path":"displayName","value":"Renamed"},{"op":"replace","path":"active","value":false}]}`, "scim-secret-token")
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

	read := authed(http.MethodGet, "/scim/v2/Users/"+userID, "", "scim-secret-token")
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, read)
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "user@example.test") {
		t.Fatalf("read status=%d body=%s", rr.Code, rr.Body.String())
	}

	put := authed(http.MethodPut, "/scim/v2/Users/"+userID, `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"externalId":"authentik-subject-1","userName":"user@example.test","displayName":"Put User","active":true,"password":"replacement-password"}`, "scim-secret-token")
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, put)
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "Put User") {
		t.Fatalf("put status=%d body=%s", rr.Code, rr.Body.String())
	}
	if got := d.DovecotPassdb("c", daemon.PassdbRequest{Username: "user@example.test", Secret: "replacement-password", Protocol: "imap"}); got.Decision != daemon.OK {
		t.Fatalf("PUT replacement password did not enter daemon passdb: %#v", got)
	}
	restarted, err := identity.NewSQLService(context.Background(), db, "example.test")
	if err != nil {
		t.Fatal(err)
	}
	restartedDaemon := &daemon.Service{}
	restarted.BindDaemon(restartedDaemon)
	restartedSCIM, err := NewSCIMHandler("https://mail.example.test/scim/v2", db, restarted, authz.StaticAuthorizer{}, audit.SQLWriter{DB: db})
	if err != nil {
		t.Fatal(err)
	}
	restartedHandler := Server{Identity: restarted, Daemon: *restartedDaemon, SCIM: restartedSCIM}.Handler()
	rr = httptest.NewRecorder()
	restartedHandler.ServeHTTP(rr, authed(http.MethodGet, "/scim/v2/Users/"+userID, "", "scim-secret-token"))
	if rr.Code != http.StatusOK || responseID(t, rr.Body.String()) != userID {
		t.Fatalf("restart read status=%d body=%s", rr.Code, rr.Body.String())
	}
	if got := restartedDaemon.DovecotPassdb("c", daemon.PassdbRequest{Username: "user@example.test", Secret: "replacement-password", Protocol: "imap"}); got.Decision != daemon.OK {
		t.Fatalf("restart lost SCIM password projection: %#v", got)
	}

	deleteReq := authed(http.MethodDelete, "/scim/v2/Users/"+userID, "", "scim-secret-token")
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, deleteReq)
	if rr.Code != http.StatusNoContent {
		t.Fatalf("delete status=%d body=%s", rr.Code, rr.Body.String())
	}
	if got := d.DovecotPassdb("c", daemon.PassdbRequest{Username: "user@example.test", Secret: "replacement-password", Protocol: "imap"}); got.Decision != daemon.Reject {
		t.Fatalf("deleted SCIM user remained enabled: %#v", got)
	}
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, authed(http.MethodPost, "/scim/v2/Users", `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"externalId":"authentik-subject-1","userName":"replacement@example.test","active":true}`, "scim-secret-token"))
	if rr.Code != http.StatusConflict {
		t.Fatalf("tombstoned external identity recreation status=%d body=%s", rr.Code, rr.Body.String())
	}

	badCases := []struct{ name, method, path, body string }{
		{"malformed", http.MethodPost, "/scim/v2/Users", `{`},
		{"non-object", http.MethodPost, "/scim/v2/Users", `[]`},
		{"scalar active", http.MethodPost, "/scim/v2/Users", `{"userName":"bad@example.test","active":"yes"}`},
		{"scalar display", http.MethodPost, "/scim/v2/Users", `{"userName":"bad@example.test","displayName":12}`},
		{"scalar formatted", http.MethodPost, "/scim/v2/Users", `{"userName":"bad@example.test","name":{"formatted":12}}`},
		{"bad domain", http.MethodPost, "/scim/v2/Users", `{"userName":"bad@evil.test"}`},
		{"empty operations", http.MethodPatch, "/scim/v2/Users/" + userID, `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[]}`},
		{"unknown path", http.MethodPatch, "/scim/v2/Users/" + userID, `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","path":"unknown","value":"x"}]}`},
		{"unsupported op", http.MethodPatch, "/scim/v2/Users/" + userID, `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"move","path":"displayName","value":"x"}]}`},
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
	h.ServeHTTP(rr, authed(http.MethodGet, "/scim/v2/Groups", "", "scim-secret-token"))
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "ListResponse") {
		t.Fatalf("groups status=%d body=%s", rr.Code, rr.Body.String())
	}
}

func TestSCIMGroupsRequireSameScopeOpaqueUsersAndRemainNonAuthoritative(t *testing.T) {
	db, ids, _, h := scimTestHandler(t, nil)
	createUser := func(token, externalID, mailbox string) string {
		t.Helper()
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, authed(http.MethodPost, "/scim/v2/Users", fmt.Sprintf(`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"externalId":%q,"userName":%q,"active":true}`, externalID, mailbox), token))
		if rr.Code != http.StatusCreated {
			t.Fatalf("create user status=%d body=%s", rr.Code, rr.Body.String())
		}
		return responseID(t, rr.Body.String())
	}
	userID := createUser("scim-secret-token", "subject-group-user", "group-user@example.test")
	if err := ids.AddToken("scim-other", "scim_client", "other-scim-secret"); err != nil {
		t.Fatal(err)
	}
	otherScopeUserID := createUser("other-scim-secret", "subject-other-scope", "other-scope@example.test")

	createGroup := func(body string) *httptest.ResponseRecorder {
		t.Helper()
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, authed(http.MethodPost, "/scim/v2/Groups", body, "scim-secret-token"))
		return rr
	}
	rr := createGroup(fmt.Sprintf(`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"externalId":"authentik-group-1","displayName":"Operators","members":[{"value":%q,"type":"User"}]}`, userID))
	if rr.Code != http.StatusCreated {
		t.Fatalf("create group status=%d body=%s", rr.Code, rr.Body.String())
	}
	groupID := responseID(t, rr.Body.String())
	var members, roles, groupAudits int
	if err := db.QueryRow(`SELECT count(*) FROM scim_group_members WHERE group_id=$1 AND user_id=$2`, groupID, userID).Scan(&members); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT count(*) FROM role_bindings`).Scan(&roles); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT count(*) FROM audit_events WHERE action='scim.group.create' AND resource_id=$1`, groupID).Scan(&groupAudits); err != nil {
		t.Fatal(err)
	}
	if members != 1 || roles != 0 || groupAudits != 1 {
		t.Fatalf("members=%d roles=%d groupAudits=%d", members, roles, groupAudits)
	}
	var scope string
	if err := db.QueryRow(`SELECT scope FROM scim_resources WHERE resource_type='Group' AND id=$1`, groupID).Scan(&scope); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO scim_group_members(scope, group_id, user_id) VALUES ($1,$2,$3)`, scope, groupID, otherScopeUserID); err == nil {
		t.Fatal("database admitted a cross-scope Group member")
	}
	otherGroup := createGroup(`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"Other Group","members":[]}`)
	if otherGroup.Code != http.StatusCreated {
		t.Fatalf("create other group status=%d body=%s", otherGroup.Code, otherGroup.Body.String())
	}
	if _, err := db.Exec(`INSERT INTO scim_group_members(scope, group_id, user_id) VALUES ($1,$2,$3)`, scope, groupID, responseID(t, otherGroup.Body.String())); err == nil {
		t.Fatal("database admitted a Group resource as a User member")
	}

	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, authed(http.MethodDelete, "/scim/v2/Users/"+userID, "", "scim-secret-token"))
	if rr.Code != http.StatusConflict {
		t.Fatalf("referenced user delete status=%d body=%s", rr.Code, rr.Body.String())
	}
	var enabled bool
	if err := db.QueryRow(`SELECT enabled FROM mailboxes WHERE scim_resource_id=$1`, userID).Scan(&enabled); err != nil || !enabled {
		t.Fatalf("failed delete disabled mailbox enabled=%v err=%v", enabled, err)
	}

	badGroups := []string{
		`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"Missing","members":[{"value":"missing-user","type":"User"}]}`,
		fmt.Sprintf(`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"CrossScope","members":[{"value":%q,"type":"User"}]}`, otherScopeUserID),
		fmt.Sprintf(`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"Nested","members":[{"value":%q,"type":"Group"}]}`, groupID),
		fmt.Sprintf(`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"Duplicate","members":[{"value":%q},{"value":%q}]}`, userID, userID),
	}
	for _, body := range badGroups {
		rr = createGroup(body)
		if rr.Code < 400 {
			t.Fatalf("invalid group admitted status=%d body=%s", rr.Code, rr.Body.String())
		}
	}

	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, authed(http.MethodPatch, "/scim/v2/Groups/"+groupID, `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","path":"members","value":[]}]}`, "scim-secret-token"))
	if rr.Code != http.StatusOK {
		t.Fatalf("clear members status=%d body=%s", rr.Code, rr.Body.String())
	}
	if err := db.QueryRow(`SELECT count(*) FROM scim_group_members WHERE group_id=$1`, groupID).Scan(&members); err != nil || members != 0 {
		t.Fatalf("members after clear=%d err=%v", members, err)
	}
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, authed(http.MethodDelete, "/scim/v2/Users/"+userID, "", "scim-secret-token"))
	if rr.Code != http.StatusNoContent {
		t.Fatalf("unreferenced user delete status=%d body=%s", rr.Code, rr.Body.String())
	}
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, authed(http.MethodDelete, "/scim/v2/Groups/"+groupID, "", "scim-secret-token"))
	if rr.Code != http.StatusNoContent {
		t.Fatalf("group delete status=%d body=%s", rr.Code, rr.Body.String())
	}
}

func TestSCIMGroupAuditFailureRollsBackResourceAndMembership(t *testing.T) {
	db, _, _, h := scimTestHandler(t, nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, authed(http.MethodPost, "/scim/v2/Users", `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"externalId":"subject","userName":"audit-user@example.test","active":true}`, "scim-secret-token"))
	if rr.Code != http.StatusCreated {
		t.Fatalf("create user status=%d body=%s", rr.Code, rr.Body.String())
	}
	userID := responseID(t, rr.Body.String())
	if _, err := db.Exec(`CREATE FUNCTION reject_group_audit() RETURNS trigger AS $$ BEGIN IF NEW.action='scim.group.create' THEN RAISE EXCEPTION 'forced group audit failure'; END IF; RETURN NEW; END; $$ LANGUAGE plpgsql; CREATE TRIGGER reject_group_audit BEFORE INSERT ON audit_events FOR EACH ROW EXECUTE FUNCTION reject_group_audit()`); err != nil {
		t.Fatal(err)
	}
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, authed(http.MethodPost, "/scim/v2/Groups", fmt.Sprintf(`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"externalId":"group","displayName":"Operators","members":[{"value":%q}]}`, userID), "scim-secret-token"))
	if rr.Code < 500 {
		t.Fatalf("audit failure status=%d body=%s", rr.Code, rr.Body.String())
	}
	for _, table := range []string{"scim_group_members", "scim_resources"} {
		var count int
		query := `SELECT count(*) FROM ` + table
		if table == "scim_resources" {
			query += ` WHERE resource_type='Group'`
		}
		if err := db.QueryRow(query).Scan(&count); err != nil || count != 0 {
			t.Fatalf("%s count=%d err=%v", table, count, err)
		}
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

func TestSCIMRenamePreservesOpaqueIDAndAuditsAuthFailure(t *testing.T) {
	w := &audit.MemoryWriter{}
	db, ids, d, h := scimTestHandler(t, w)
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
	h.ServeHTTP(rr, authed(http.MethodPost, "/scim/v2/Users", `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"user@example.test","password":"long-password"}`, "scim-secret-token"))
	if rr.Code != http.StatusCreated {
		t.Fatalf("create status=%d body=%s", rr.Code, rr.Body.String())
	}
	userID := responseID(t, rr.Body.String())
	created, err := ids.CreateAppPassword(context.Background(), authz.Actor{Type: "local_admin", ID: "test-admin"}, "user@example.test", "phone")
	if err != nil {
		t.Fatal(err)
	}
	if got := d.DovecotPassdb("c", daemon.PassdbRequest{Username: "user@example.test", Secret: created.SecretOnce, Protocol: "imap"}); got.Decision != daemon.OK {
		t.Fatalf("pre-rename app password rejected: %#v", got)
	}
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, authed(http.MethodPut, "/scim/v2/Users/"+userID, `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"other@example.test","active":true}`, "scim-secret-token"))
	if rr.Code != http.StatusOK || responseID(t, rr.Body.String()) != userID || !strings.Contains(rr.Body.String(), "other@example.test") {
		t.Fatalf("rename status=%d body=%s", rr.Code, rr.Body.String())
	}
	if got := d.DovecotPassdb("c", daemon.PassdbRequest{Username: "user@example.test", Secret: created.SecretOnce, Protocol: "imap"}); got.Decision != daemon.NotFound {
		t.Fatalf("renamed mailbox lingered at old address: %#v", got)
	}
	if got := d.DovecotPassdb("c", daemon.PassdbRequest{Username: "other@example.test", Secret: created.SecretOnce, Protocol: "imap"}); got.Decision != daemon.OK {
		t.Fatalf("renamed mailbox lost app password: %#v", got)
	}
	restarted, err := identity.NewSQLService(context.Background(), db, "example.test")
	if err != nil {
		t.Fatal(err)
	}
	restartedDaemon := &daemon.Service{}
	restarted.BindDaemon(restartedDaemon)
	if got := restartedDaemon.DovecotPassdb("c", daemon.PassdbRequest{Username: "user@example.test", Secret: created.SecretOnce, Protocol: "imap"}); got.Decision != daemon.NotFound {
		t.Fatalf("restart restored old renamed address: %#v", got)
	}
	if got := restartedDaemon.DovecotPassdb("c", daemon.PassdbRequest{Username: "other@example.test", Secret: created.SecretOnce, Protocol: "imap"}); got.Decision != daemon.OK {
		t.Fatalf("restart lost renamed app password: %#v", got)
	}
}

func TestSCIMFailsClosedWithoutConfiguredRuntime(t *testing.T) {
	h := Server{Daemon: daemon.Service{Domains: map[string]daemon.Domain{"example.test": {Name: "example.test", Enabled: true}}}}.Handler()
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/scim/v2/Users", strings.NewReader(`{"userName":"user@example.test"}`)))
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d", rr.Code)
	}
}

func TestSCIMAuditFailureRollsBackResourceAndMailbox(t *testing.T) {
	db, _, _, h := scimTestHandler(t, nil)
	if _, err := db.Exec(`ALTER TABLE audit_events ADD CONSTRAINT reject_scim_create CHECK (action <> 'scim.user.create')`); err != nil {
		t.Fatal(err)
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, authed(http.MethodPost, "/scim/v2/Users", `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"rollback@example.test","password":"long-password"}`, "scim-secret-token"))
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	for _, table := range []string{"scim_resources", "mailboxes"} {
		var count int
		if err := db.QueryRow(`SELECT count(*) FROM ` + table).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != 0 {
			t.Fatalf("%s retained %d rows after audit failure", table, count)
		}
	}
}

func TestSCIMConcurrentCreateHasOneWinner(t *testing.T) {
	_, _, _, h := scimTestHandler(t, nil)
	const contenders = 8
	statuses := make(chan int, contenders)
	start := make(chan struct{})
	var workers sync.WaitGroup
	for index := 0; index < contenders; index++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			<-start
			rr := httptest.NewRecorder()
			h.ServeHTTP(rr, authed(http.MethodPost, "/scim/v2/Users", `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"concurrent@example.test","active":true}`, "scim-secret-token"))
			statuses <- rr.Code
		}()
	}
	close(start)
	workers.Wait()
	close(statuses)
	winners, conflicts := 0, 0
	for status := range statuses {
		switch status {
		case http.StatusCreated:
			winners++
		case http.StatusConflict:
			conflicts++
		default:
			t.Fatalf("unexpected concurrent status %d", status)
		}
	}
	if winners != 1 || conflicts != contenders-1 {
		t.Fatalf("winners=%d conflicts=%d", winners, conflicts)
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

func TestV3MailuImportAPIUsesSQLCanonicalApplyWhenConfigured(t *testing.T) {
	db := testpg.DB(t, store.MigrateSQL)
	ids := identity.NewService("example.test")
	if err := ids.AddTokenWithScopes("ops", "api_token", "ops-secret-token", "ops:admin"); err != nil {
		t.Fatal(err)
	}
	source, err := os.ReadFile("../../test/fixtures/mailu/config-export-secrets.json")
	if err != nil {
		t.Fatal(err)
	}
	h := Server{AuditDB: db, Identity: ids}.Handler()
	body, _ := json.Marshal(map[string]string{"source": string(source)})
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, v3Req(http.MethodPost, "/api/v1/imports/mailu/preview", string(body)))
	if rr.Code != http.StatusOK {
		t.Fatalf("preview status=%d body=%s", rr.Code, rr.Body.String())
	}
	var p ops.ImportPreview
	if err := json.Unmarshal(rr.Body.Bytes(), &p); err != nil {
		t.Fatal(err)
	}
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, v3Req(http.MethodPost, "/api/v1/imports/mailu/apply?hash="+p.Hash+"&source_fingerprint="+p.SourceFingerprint, `{"id":"`+p.ID+`"}`))
	if rr.Code != http.StatusOK {
		t.Fatalf("apply status=%d body=%s", rr.Code, rr.Body.String())
	}
	var count int
	if err := db.QueryRow(`SELECT count(*) FROM mailboxes`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 2 {
		t.Fatalf("mailbox count=%d", count)
	}
	if err := db.QueryRow(`SELECT count(*) FROM audit_events WHERE action='import.mailu.apply'`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("import audit count=%d", count)
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
func (f apiFakeIMAP) ListFoldersDetailed(context.Context, string) ([]webmail.FolderInfo, error) {
	return []webmail.FolderInfo{{Name: "INBOX", Unread: 2}}, nil
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
func (f apiFakeIMAP) Quota(context.Context, string) (int64, int64, error) { return 0, 0, nil }
func (f apiFakeIMAP) SetFlag(context.Context, string, string, string, string, bool) error {
	return nil
}
func (f apiFakeIMAP) Move(context.Context, string, string, string, string) error { return nil }
func (f apiFakeIMAP) Delete(context.Context, string, string, string) error       { return nil }

type apiFakeSMTP struct{ sent bool }

func (f *apiFakeSMTP) Submit(context.Context, webmail.Envelope, []byte) error {
	f.sent = true
	return nil
}

type apiFakeSigner struct{}

func (apiFakeSigner) SignMIME(ctx context.Context, id webmail.Identity, b []byte) ([]byte, webmail.SignatureStatus, error) {
	return append([]byte("From: "+id.Address+"\r\nMIME-Version: 1.0\r\nContent-Type: multipart/signed; protocol=\"application/pgp-signature\"; micalg=pgp-sha256; boundary=\"sig\"\r\n\r\n--sig\r\nContent-Type: multipart/mixed; boundary=\"fake\"\r\nX-GOTTH-Mail-Signed-From: "+id.Address+"\r\nX-GOTTH-Mail-Signing-Fingerprint: "+id.Fingerprint+"\r\n\r\n"), append(b, []byte("\r\n--sig\r\nContent-Type: application/pgp-signature\r\n\r\n-----BEGIN PGP SIGNATURE-----\r\n\r\nfake-signature\r\n-----END PGP SIGNATURE-----\r\n--sig--\r\n")...)...), webmail.SignatureStatus{Fingerprint: id.Fingerprint, Identity: id.Address, Signed: true}, nil
}

func (apiFakeSigner) VerifyExactSender(ctx context.Context, signed []byte, id webmail.Identity) (webmail.SignatureStatus, error) {
	return webmail.SignatureStatus{Fingerprint: id.Fingerprint, Identity: id.Address, Signed: true}, nil
}

type apiFakeResolver struct{}

type apiFakeOutboundPolicy struct{}

func (apiFakeOutboundPolicy) Decide(context.Context, string, outboundpolicy.EnforcementRequest) (outboundpolicy.Decision, error) {
	return outboundpolicy.Decision{Action: outboundpolicy.ActionOK, Reason: outboundpolicy.ReasonUnrestricted}, nil
}

func (apiFakeResolver) ResolveSender(ctx context.Context, fp, from, sender string) (webmail.Identity, error) {
	return webmail.Identity{Address: from, Fingerprint: fp}, nil
}
func (apiFakeResolver) DefaultIdentity(ctx context.Context, mailbox string) (webmail.Identity, error) {
	return webmail.Identity{Address: mailbox, Fingerprint: "fp"}, nil
}

func webmailServer(t *testing.T, smtp *apiFakeSMTP) http.Handler {
	t.Helper()
	ids := identity.NewService("example.test")
	if err := ids.AddTokenWithScopes("web-user-token", "api_token", "web-secret-token", "mailbox:web-user@example.test:webmail:use"); err != nil {
		t.Fatal(err)
	}
	client := &webmail.Client{IMAP: apiFakeIMAP{messages: []webmail.Message{{ID: "m1", Folder: "INBOX", From: "A User <a@example.test>", Subject: "Hi", BodyHTML: "<script>x</script><b>safe</b>", Attachments: []webmail.Attachment{{Filename: "note.txt", ContentType: "text/plain", Size: 5, Content: []byte("hello")}}}}}}
	sender := &webmail.Sender{Drafts: map[string]webmail.Draft{}, SMTP: smtp, Signer: apiFakeSigner{}, Resolver: apiFakeResolver{}, Policy: apiFakeOutboundPolicy{}, Audit: &audit.MemoryWriter{}}
	return Server{Identity: ids, WebmailClient: client, WebmailSender: sender}.Handler()
}

func TestWebmailShellIsReachableWithoutRoundcube(t *testing.T) {
	h := webmailServer(t, &apiFakeSMTP{})
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/webmail", nil))
	body := rr.Body.String()
	for _, want := range []string{"GOTTH Mail", "command-actions", "folder-pane", "message-list", "reader-pane", "composer", "/webmail/assets/app.js", "gotth-footer", "Powered by", "Version: <strong>dev</strong>", "Page: <strong>", "Template: <strong>"} {
		if rr.Code != http.StatusOK || !strings.Contains(body, want) {
			t.Fatalf("webmail shell status=%d missing %q body=%s", rr.Code, want, body)
		}
	}
	if got := rr.Header().Get("Content-Security-Policy"); !strings.Contains(got, "default-src 'none'") || !strings.Contains(got, "script-src 'self'") || !strings.Contains(got, "trusted-types 'none'") {
		t.Fatalf("webmail CSP=%q", got)
	}
	if got := rr.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("webmail cache control=%q", got)
	}
	asset := httptest.NewRecorder()
	h.ServeHTTP(asset, httptest.NewRequest(http.MethodGet, "/webmail/assets/app.js", nil))
	if asset.Code != http.StatusOK || !strings.Contains(asset.Body.String(), "mark_read") || !strings.Contains(asset.Body.String(), "gotth_mail_csrf") {
		t.Fatalf("webmail JS status=%d body=%s", asset.Code, asset.Body.String())
	}
	if got := asset.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("webmail asset cache control=%q", got)
	}
	stylesheet := httptest.NewRecorder()
	h.ServeHTTP(stylesheet, httptest.NewRequest(http.MethodGet, "/webmail/assets/app.css", nil))
	css := stylesheet.Body.String()
	for _, want := range []string{".gotth-footer", ".gotth-footer-product", ".command-actions", "@media(max-width:900px)", "min(var(--folder-width),28vw)", "#compose-form{height:auto;min-height:100%;overflow:auto"} {
		if stylesheet.Code != http.StatusOK || !strings.Contains(css, want) {
			t.Fatalf("webmail CSS status=%d missing %q body=%s", stylesheet.Code, want, css)
		}
	}
}

func TestWebmailFooterEscapesReleaseIdentity(t *testing.T) {
	body := renderWebmailApp(time.Now(), `<script>alert("release")</script>`)
	if strings.Contains(body, `<script>alert("release")</script>`) || !strings.Contains(body, `&lt;script&gt;alert(&#34;release&#34;)&lt;/script&gt;`) {
		t.Fatalf("unsafe release identity in webmail footer: %s", body)
	}
}

func TestLiveContainerWebmailShellReachable(t *testing.T) {
	base := os.Getenv("GOTTH_MAIL_LIVE_WEBMAIL_UI_URL")
	if base == "" {
		t.Skip("GOTTH_MAIL_LIVE_WEBMAIL_UI_URL not set")
	}
	resp, err := http.Get(strings.TrimRight(base, "/") + "/webmail")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	body := string(b)
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, "GOTTH Mail") || !strings.Contains(body, "message-list") || !strings.Contains(body, "composer") {
		t.Fatalf("webmail UI status=%d body=%s", resp.StatusCode, body)
	}
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
	req = v3Req(http.MethodGet, "/api/v1/webmail/quota", "")
	req.Header.Set("Authorization", "Bearer web-secret-token")
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "used_bytes") {
		t.Fatalf("quota status=%d body=%s", rr.Code, rr.Body.String())
	}
	req = v3Req(http.MethodGet, "/api/v1/webmail/identity", "")
	req.Header.Set("Authorization", "Bearer web-secret-token")
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), `"signing_fingerprint":"fp"`) {
		t.Fatalf("identity status=%d body=%s", rr.Code, rr.Body.String())
	}
	req = v3Req(http.MethodPost, "/api/v1/webmail/message?folder=INBOX&id=m1", `{"action":"mark_read"}`)
	req.Header.Set("Authorization", "Bearer web-secret-token")
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("message action status=%d body=%s", rr.Code, rr.Body.String())
	}
	req = v3Req(http.MethodPost, "/api/v1/webmail/message?folder=INBOX&id=m1", `{"action":"mark_read"} {}`)
	req.Header.Set("Authorization", "Bearer web-secret-token")
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("trailing message action JSON status=%d body=%s", rr.Code, rr.Body.String())
	}
	req = v3Req(http.MethodGet, "/api/v1/webmail/messages/INBOX/m1", "")
	req.Header.Set("Authorization", "Bearer web-secret-token")
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK || strings.Contains(rr.Body.String(), "<script>") {
		t.Fatalf("read status=%d body=%s", rr.Code, rr.Body.String())
	}
	req = v3Req(http.MethodGet, "/api/v1/webmail/message?folder=INBOX&id=m1", "")
	req.Header.Set("Authorization", "Bearer web-secret-token")
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	var queryMessage webmail.Message
	if err := json.Unmarshal(rr.Body.Bytes(), &queryMessage); err != nil {
		t.Fatal(err)
	}
	if rr.Code != http.StatusOK || queryMessage.From != "A User <a@example.test>" {
		t.Fatalf("query read status=%d body=%s", rr.Code, rr.Body.String())
	}
	req = v3Req(http.MethodGet, "/api/v1/webmail/attachment?folder=INBOX&id=m1&index=0", "")
	req.Header.Set("Authorization", "Bearer web-secret-token")
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK || rr.Body.String() != "hello" || rr.Header().Get("Content-Type") != "application/octet-stream" || !strings.Contains(rr.Header().Get("Content-Disposition"), "attachment") {
		t.Fatalf("attachment status=%d headers=%v body=%q", rr.Code, rr.Header(), rr.Body.String())
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
	req = v3Req(http.MethodGet, "/api/v1/webmail/drafts", "")
	req.Header.Set("Authorization", "Bearer web-secret-token")
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), d.ID) || strings.Contains(rr.Body.String(), `"Body"`) || strings.Contains(rr.Body.String(), `"Attachments"`) {
		t.Fatalf("draft list status=%d body=%s", rr.Code, rr.Body.String())
	}
	req = v3Req(http.MethodGet, "/api/v1/webmail/drafts/"+d.ID, "")
	req.Header.Set("Authorization", "Bearer web-secret-token")
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), `"Body":"b"`) {
		t.Fatalf("draft detail status=%d body=%s", rr.Code, rr.Body.String())
	}
	req = v3Req(http.MethodPut, "/api/v1/webmail/drafts/"+d.ID, `{"to":"updated@example.test","subject":"updated","body":"updated body"}`)
	req.Header.Set("Authorization", "Bearer web-secret-token")
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("draft update status=%d body=%s", rr.Code, rr.Body.String())
	}
	var updated webmail.Draft
	if err := json.Unmarshal(rr.Body.Bytes(), &updated); err != nil {
		t.Fatal(err)
	}
	if updated.ID != d.ID || updated.From != "web-user@example.test" || updated.To != "updated@example.test" || updated.Subject != "updated" || updated.SigningFingerprint != "fp" {
		t.Fatalf("updated draft=%+v", updated)
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
	sender := &webmail.Sender{Drafts: map[string]webmail.Draft{}, SMTP: smtp, Signer: apiFakeSigner{}, Resolver: apiFakeResolver{}, Policy: apiFakeOutboundPolicy{}, Audit: &audit.MemoryWriter{}}
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

func TestWebmailAPIUsesSQLDraftStoreWhenConfigured(t *testing.T) {
	db := testpg.DB(t, store.MigrateSQL)
	ids := identity.NewService("example.test")
	if err := ids.AddTokenWithScopes("web-user-token", "api_token", "web-secret-token", "mailbox:web-user@example.test:webmail:use"); err != nil {
		t.Fatal(err)
	}
	smtp := &apiFakeSMTP{}
	sender := &webmail.Sender{SMTP: smtp, Signer: apiFakeSigner{}, Resolver: apiFakeResolver{}, Policy: apiFakeOutboundPolicy{}, Audit: &audit.MemoryWriter{}}
	h := Server{AuditDB: db, Identity: ids, WebmailClient: &webmail.Client{IMAP: apiFakeIMAP{}}, WebmailSender: sender}.Handler()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/webmail/drafts", strings.NewReader(`{"id":"attacker-chosen","from":"web-user@example.test","to":"r@example.test","subject":"s","body":"b","replyto":"imap-42","forwardof":"imap-17","signingfingerprint":"fp","attachments":[{"filename":"note.txt","contenttype":"text/plain","size":5,"content":"aGVsbG8="}]}`))
	req.Header.Set("Authorization", "Bearer web-secret-token")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("draft status=%d body=%s", rr.Code, rr.Body.String())
	}
	var d webmail.Draft
	if err := json.Unmarshal(rr.Body.Bytes(), &d); err != nil {
		t.Fatal(err)
	}
	if d.ID == "attacker-chosen" {
		t.Fatal("API accepted caller-supplied draft id")
	}
	var mailbox string
	if err := db.QueryRow(`SELECT mailbox FROM webmail_drafts WHERE id=$1`, d.ID).Scan(&mailbox); err != nil {
		t.Fatal(err)
	}
	if mailbox != "web-user@example.test" {
		t.Fatalf("mailbox=%q", mailbox)
	}
	stored, ok, err := (webmail.SQLDraftStore{DB: db}).Draft(context.Background(), d.ID)
	if err != nil || !ok {
		t.Fatalf("ok=%v err=%v", ok, err)
	}
	if stored.ReplyTo != "imap-42" || stored.ForwardOf != "imap-17" || len(stored.Attachments) != 1 || stored.Attachments[0].Filename != "note.txt" || string(stored.Attachments[0].Content) != "hello" {
		t.Fatalf("draft metadata not persisted: %#v", stored)
	}
	req = httptest.NewRequest(http.MethodPost, "/api/v1/webmail/drafts/"+d.ID+"/submit", nil)
	req.Header.Set("Authorization", "Bearer web-secret-token")
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK || !smtp.sent {
		t.Fatalf("submit status=%d body=%s sent=%v", rr.Code, rr.Body.String(), smtp.sent)
	}
	var state string
	if err := db.QueryRow(`SELECT state FROM webmail_drafts WHERE id=$1`, d.ID).Scan(&state); err != nil {
		t.Fatal(err)
	}
	if state != "sent" {
		t.Fatalf("state=%q", state)
	}
}

func TestNotificationDeliveryStatusAPIUsesSQLRecorderWhenConfigured(t *testing.T) {
	db := testpg.DB(t, store.MigrateSQL)
	ids := identity.NewService("example.test")
	if err := ids.AddTokenWithScopes("notify-reader", "api_token", "notify-secret", "notification:read", "notification:read:alert-1"); err != nil {
		t.Fatal(err)
	}
	rec := notification.SQLRecorder{DB: db}
	if err := rec.RecordPending(context.Background(), notification.Alert{ID: "alert-1", Class: "backup.failure", Severity: notification.SeverityCritical, Title: "Backup failed", Summary: "password=hunter2 failed", Resource: notification.ResourceRef{Type: "backup", ID: "artifact-1"}}, time.Unix(1, 0)); err != nil {
		t.Fatal(err)
	}
	if err := rec.RecordFinal(context.Background(), "alert-1", notification.StatusFailedPermanent, "plugin_rejected", notification.DeliveryEvidence{}, time.Unix(2, 0)); err != nil {
		t.Fatal(err)
	}
	h := Server{AuditDB: db, Identity: ids}.Handler()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/notifications/deliveries", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("unauth status=%d body=%s", rr.Code, rr.Body.String())
	}
	req = httptest.NewRequest(http.MethodGet, "/api/v1/notifications/deliveries", nil)
	req.Header.Set("Authorization", "Bearer notify-secret")
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "failed_permanent") || strings.Contains(rr.Body.String(), "hunter2") || !strings.Contains(rr.Body.String(), "[REDACTED]") {
		t.Fatalf("list status=%d body=%s", rr.Code, rr.Body.String())
	}
	req = httptest.NewRequest(http.MethodGet, "/api/v1/notifications/deliveries/alert-1", nil)
	req.Header.Set("Authorization", "Bearer notify-secret")
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "plugin_rejected") || !strings.Contains(rr.Body.String(), "backup.failure") {
		t.Fatalf("detail status=%d body=%s", rr.Code, rr.Body.String())
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
	restoreDB := testpg.DB(t, nil)
	rt.RestoreEngine = ops.SQLIsolatedRestoreEngine{DB: restoreDB, Ref: "api-isolated-restore"}
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
	if got.Status != "verified" || got.ConfigSetID != "cfg" || got.IsolatedRestoreRef != "api-isolated-restore" {
		t.Fatalf("latest=%#v", got)
	}
}

func TestV3SnapshotsReadPersistedSQLLinkage(t *testing.T) {
	db := testpg.DB(t, store.MigrateSQL)
	ids := identity.NewService("example.test")
	if err := ids.AddTokenWithScopes("ops-admin", "api_token", "ops-secret-token", "ops:admin"); err != nil {
		t.Fatal(err)
	}
	storage := ops.MemoryBackupStorage{Artifacts: map[string]ops.BackupArtifact{"artifact": {SchemaVersion: "schema_migrations", ConfigSetID: "cfg", Domains: map[string]daemon.Domain{"example.test": {Name: "example.test", Enabled: true}}, Mailboxes: map[string]daemon.Mailbox{"user@example.test": {Address: "user@example.test", Enabled: true}}}}}
	backupStore := ops.SQLBackupVerificationStore{DB: db}
	if _, err := backupStore.VerifyAndRecord(context.Background(), storage, "artifact", "plugin-backup", "snapshot-restore", time.Unix(10, 0)); err != nil {
		t.Fatal(err)
	}
	latest, ok, err := backupStore.Latest(context.Background(), "artifact")
	if err != nil || !ok {
		t.Fatalf("latest ok=%v err=%v", ok, err)
	}
	if _, err := (ops.SQLSnapshotStore{DB: db}).Capture(context.Background(), ops.SnapshotView{ID: "00000000-0000-4000-8000-000000000401", MigrationVersion: "schema_migrations", DeploymentPolicyHash: "policy-a", LinkedBackupVerificationID: latest.ID, ImageVersions: []string{"gotth-mail@sha256:1"}}, time.Unix(20, 0)); err != nil {
		t.Fatal(err)
	}
	if _, err := (ops.SQLSnapshotStore{DB: db}).Capture(context.Background(), ops.SnapshotView{ID: "00000000-0000-4000-8000-000000000402", MigrationVersion: "schema_migrations", DeploymentPolicyHash: "policy-b", ImageVersions: []string{"gotth-mail@sha256:2"}}, time.Unix(30, 0)); err != nil {
		t.Fatal(err)
	}
	h := Server{AuditDB: db, Identity: ids}.Handler()
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, v3Req(http.MethodGet, "/api/v1/snapshots", ""))
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "verified") {
		t.Fatalf("list status=%d body=%s", rr.Code, rr.Body.String())
	}
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, v3Req(http.MethodGet, "/api/v1/snapshots/00000000-0000-4000-8000-000000000401", ""))
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "rollback may proceed") {
		t.Fatalf("get status=%d body=%s", rr.Code, rr.Body.String())
	}
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, v3Req(http.MethodGet, "/api/v1/snapshots/00000000-0000-4000-8000-000000000401/diff?against=00000000-0000-4000-8000-000000000402", ""))
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "deployment_policy") || !strings.Contains(rr.Body.String(), "image_versions") {
		t.Fatalf("diff status=%d body=%s", rr.Code, rr.Body.String())
	}
}

func TestV3BulkApplyUsesSQLCanonicalStateWhenConfigured(t *testing.T) {
	db := testpg.DB(t, store.MigrateSQL)
	if _, err := db.Exec(`INSERT INTO domains(id, name, created_at, updated_at) VALUES ($1,$2,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)`, "00000000-0000-4000-8000-000000000601", "example.test"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO mailboxes(id, domain_id, local_part, enabled, created_at, updated_at) VALUES ($1,$2,$3,true,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)`, "00000000-0000-4000-8000-000000000602", "00000000-0000-4000-8000-000000000601", "user"); err != nil {
		t.Fatal(err)
	}
	ids := identity.NewService("example.test")
	if err := ids.AddTokenWithScopes("ops-admin", "api_token", "ops-secret-token", "ops:admin"); err != nil {
		t.Fatal(err)
	}
	h := Server{AuditDB: db, Identity: ids}.Handler()
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, v3Req(http.MethodPost, "/api/v1/bulk/disable-users/preview", `{"items":["user@example.test"]}`))
	if rr.Code != http.StatusOK {
		t.Fatalf("preview status=%d body=%s", rr.Code, rr.Body.String())
	}
	var bp ops.BulkPreview
	if err := json.Unmarshal(rr.Body.Bytes(), &bp); err != nil {
		t.Fatal(err)
	}
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, v3Req(http.MethodPost, "/api/v1/bulk/disable-users/apply?confirm="+bp.ID+"&hash="+bp.Hash, `{"id":"`+bp.ID+`"}`))
	if rr.Code != http.StatusOK {
		t.Fatalf("apply status=%d body=%s", rr.Code, rr.Body.String())
	}
	var enabled bool
	if err := db.QueryRow(`SELECT enabled FROM mailboxes WHERE id=$1`, "00000000-0000-4000-8000-000000000602").Scan(&enabled); err != nil {
		t.Fatal(err)
	}
	if enabled {
		t.Fatal("bulk API left mailbox enabled")
	}
	events, err := (ops.SQLAuditStore{DB: db}).Query(context.Background(), ops.AuditFilter{Action: "bulk.disable-users"}, 10)
	if err != nil || len(events) != 1 {
		t.Fatalf("events=%#v err=%v", events, err)
	}
}
