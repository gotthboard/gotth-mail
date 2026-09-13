package httpui

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"forgejo/gotthboard/gotth-mail/internal/admin"
	"forgejo/gotthboard/gotth-mail/internal/authn"
	"forgejo/gotthboard/gotth-mail/internal/authz"
	"forgejo/gotthboard/gotth-mail/internal/identity"
)

type uiSessionStore struct {
	bound authn.BoundSession
}

func (s uiSessionStore) PutIdentitySession(context.Context, authn.Identity, authn.Session) (authn.Session, error) {
	return authn.Session{}, nil
}

func (s uiSessionStore) BoundSession(_ context.Context, id string, now time.Time) (authn.BoundSession, bool) {
	return s.bound, id == s.bound.ID && now.Before(s.bound.ExpiresAt)
}

func csrfHash(secret string) string {
	digest := sha256.Sum256([]byte(secret))
	return base64.RawURLEncoding.EncodeToString(digest[:])
}

func withIdentityCookies(req *http.Request, session, csrf string) {
	req.AddCookie(&http.Cookie{Name: "gotth_mail_session", Value: session})
	req.AddCookie(&http.Cookie{Name: "gotth_mail_csrf", Value: csrf})
}

func uiToken(t *testing.T, ids *identity.Service, secret string, scopes ...string) string {
	t.Helper()
	if err := ids.AddTokenWithScopes(secret+"-id", "api_token", secret, scopes...); err != nil {
		t.Fatal(err)
	}
	return "Bearer " + secret
}

func formReq(method, path string, form url.Values, bearer string) *http.Request {
	req := httptest.NewRequest(method, path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if bearer != "" {
		req.Header.Set("Authorization", bearer)
	}
	return req
}

func TestMailAdminCRUDScreensRenderAndMutate(t *testing.T) {
	s := admin.NewStore()
	ids := identity.NewService("example.test")
	bearer := uiToken(t, ids, "admin-ui-secret", "domain:admin:example.test", "mailbox:admin:smoke@example.test", "alias:admin:alias@example.test")
	h := HandlerWithAdminAndIdentity(s, ids, authz.StaticAuthorizer{})
	form := url.Values{"name": {"Example.Test"}, "enabled": {"on"}}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, formReq(http.MethodPost, "/admin/domains", form, ""))
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("unauth domain mutation status=%d", w.Code)
	}
	w = httptest.NewRecorder()
	h.ServeHTTP(w, formReq(http.MethodPost, "/admin/domains", form, bearer))
	if w.Code != http.StatusOK {
		t.Fatalf("domain status=%d", w.Code)
	}
	form = url.Values{"address": {"Smoke@Example.Test"}, "enabled": {"on"}}
	w = httptest.NewRecorder()
	h.ServeHTTP(w, formReq(http.MethodPost, "/admin/users", form, bearer))
	if w.Code != http.StatusOK {
		t.Fatalf("user status=%d", w.Code)
	}
	form = url.Values{"address": {"Alias@Example.Test"}, "targets": {"Smoke@Example.Test"}, "enabled": {"on"}}
	w = httptest.NewRecorder()
	h.ServeHTTP(w, formReq(http.MethodPost, "/admin/aliases", form, bearer))
	if w.Code != http.StatusOK {
		t.Fatalf("alias status=%d", w.Code)
	}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)
	body, _ := io.ReadAll(w.Result().Body)
	text := string(body)
	for _, want := range []string{"Domain CRUD", "User CRUD", "Alias CRUD", "example.test", "smoke@example.test", "alias@example.test", "OIDC/Auth status", "Authentik role/group mapping", "SCIM capability/status", "App passwords", "Permission Simulator", "Audit UI/search/export", "Backup/restore verification", "Snapshot/rollback guidance", "Mailu import preview/apply", "Abuse/rate-limit dashboard", "Bulk admin workflows", "Doctor screens", "DNS/DKIM screens", "Plugin status/config screens", "Lookup debugger UI"} {
		if !strings.Contains(text, want) {
			t.Fatalf("admin UI missing %q in %s", want, text)
		}
	}
}

func TestIdentityUIFailsClosedUntilOIDCSubjectBindingExists(t *testing.T) {
	ids := identity.NewService("example.test")
	_, err := ids.CreateOrReplaceUser(nil, authz.Actor{Type: "local_admin", ID: "seed"}, identity.Mailbox{Email: "private-account@example.test", Active: true}, "mail-password")
	if err != nil {
		t.Fatal(err)
	}
	ids.Secret = func() (string, error) { return "never-render-this-secret", nil }
	created, err := ids.CreateAppPassword(nil, authz.Actor{Type: "local_admin", ID: "seed"}, "private-account@example.test", "private-phone-label")
	if err != nil {
		t.Fatal(err)
	}
	h := HandlerWithAdminAndIdentity(admin.NewStore(), ids, authz.StaticAuthorizer{})
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))
	body, _ := io.ReadAll(w.Result().Body)
	text := string(body)
	if w.Code != http.StatusOK || !strings.Contains(text, "Browser self-service is unavailable") || !strings.Contains(text, "gotth-scim service endpoint") {
		t.Fatalf("status=%d body=%s", w.Code, text)
	}
	for _, forbidden := range []string{"private-account@example.test", "private-phone-label", created.ID, created.SecretOnce, `action="/identity/scim-test"`, `action="/identity/app-passwords"`} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("identity UI disclosed or exposed forbidden value %q in %s", forbidden, text)
		}
	}
	for _, path := range []string{"/identity/scim-test", "/identity/app-passwords", "/identity/app-passwords/revoke"} {
		w = httptest.NewRecorder()
		h.ServeHTTP(w, formReq(http.MethodPost, path, url.Values{}, "Bearer irrelevant"))
		if w.Code != http.StatusNotFound {
			t.Fatalf("legacy identity UI path %s status=%d", path, w.Code)
		}
	}
}

func TestBoundIdentityAppPasswordUIRequiresCSRFAndShowsSecretOnce(t *testing.T) {
	now := time.Date(2026, 9, 13, 20, 0, 0, 0, time.UTC)
	ids := identity.NewService("example.test")
	ids.Now = func() time.Time { return now }
	ids.Secret = func() (string, error) { return "one-time-ui-secret-value", nil }
	if _, err := ids.CreateOrReplaceUser(context.Background(), authz.Actor{Type: "local_admin", ID: "seed"}, identity.Mailbox{Email: "user@example.test", Active: true}, "primary-mail-password"); err != nil {
		t.Fatal(err)
	}
	const sessionID = "session-bound-to-user"
	const csrf = "separate-csrf-secret"
	sessions := uiSessionStore{bound: authn.BoundSession{Session: authn.Session{ID: sessionID, IdentityRefID: "identity-ref", CreatedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour), CSRFSecretHash: csrfHash(csrf)}, Issuer: "https://auth.example.test/", Subject: "subject-1", Mailbox: "user@example.test"}}
	h := HandlerWithAdminIdentityAndSessions(admin.NewStore(), ids, authz.StaticAuthorizer{}, sessions, func() time.Time { return now })

	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/identity/app-passwords", nil))
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("missing session status=%d", w.Code)
	}

	w = httptest.NewRecorder()
	req := formReq(http.MethodPost, "/identity/app-passwords", url.Values{"action": {"create"}, "label": {"phone"}}, "")
	withIdentityCookies(req, sessionID, csrf)
	h.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("missing form CSRF status=%d", w.Code)
	}

	w = httptest.NewRecorder()
	req = formReq(http.MethodPost, "/identity/app-passwords", url.Values{"action": {"create"}, "label": {"phone"}, "csrf_token": {csrf}}, "")
	withIdentityCookies(req, sessionID, csrf)
	h.ServeHTTP(w, req)
	body := w.Body.String()
	if w.Code != http.StatusOK || !strings.Contains(body, "one-time-ui-secret-value") || !strings.Contains(body, "phone") {
		t.Fatalf("create status=%d body=%s", w.Code, body)
	}
	if w.Header().Get("Cache-Control") != "no-store" || !strings.Contains(w.Header().Get("Content-Security-Policy"), "default-src 'none'") {
		t.Fatalf("missing response hardening headers: %v", w.Header())
	}
	apps := ids.ListAppPasswords("user@example.test")
	if len(apps) != 1 || apps[0].Verifier == "" || strings.Contains(body, apps[0].Verifier) {
		t.Fatalf("stored credential mismatch or verifier disclosure: %#v", apps)
	}

	w = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/identity/app-passwords", nil)
	withIdentityCookies(req, sessionID, csrf)
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK || strings.Contains(w.Body.String(), "one-time-ui-secret-value") {
		t.Fatalf("secret repeated on later GET: status=%d body=%s", w.Code, w.Body.String())
	}

	w = httptest.NewRecorder()
	req = formReq(http.MethodPost, "/identity/app-passwords", url.Values{"action": {"revoke"}, "credential_id": {apps[0].ID}, "csrf_token": {csrf}}, "")
	withIdentityCookies(req, sessionID, csrf)
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "app password revoked") {
		t.Fatalf("revoke status=%d body=%s", w.Code, w.Body.String())
	}
	if current := ids.ListAppPasswords("user@example.test"); len(current) != 1 || current[0].RevokedAt == nil {
		t.Fatalf("credential not revoked: %#v", current)
	}
}

func TestV3OperatorUIFormsRequireAdminAndDoNotFakeBackupSuccess(t *testing.T) {
	ids := identity.NewService("example.test")
	bearer := uiToken(t, ids, "ops-ui-secret", "ops:admin")
	h := HandlerWithAdminAndIdentity(admin.NewStore(), ids, authz.StaticAuthorizer{})
	cases := []struct {
		path string
		form url.Values
		want string
	}{
		{"/ops/backup-verify", url.Values{"artifact_ref": {"ui-backup"}}, "backup verification unavailable: no configured backup storage"},
		{"/ops/mailu-preview", url.Values{"source": {`[{"Type":"domain","ID":"example.test"}]`}}, "mailu preview created:"},
		{"/ops/bulk-preview", url.Values{"operation": {"disable-users"}, "items": {"user@example.test"}}, "bulk preview created:"},
	}
	for _, tc := range cases {
		t.Run(tc.path, func(t *testing.T) {
			w := httptest.NewRecorder()
			h.ServeHTTP(w, formReq(http.MethodPost, tc.path, tc.form, ""))
			if w.Code != http.StatusUnauthorized {
				t.Fatalf("unauth status=%d", w.Code)
			}
			w = httptest.NewRecorder()
			h.ServeHTTP(w, formReq(http.MethodPost, tc.path, tc.form, bearer))
			body, _ := io.ReadAll(w.Result().Body)
			if w.Code != http.StatusOK || !strings.Contains(string(body), tc.want) {
				t.Fatalf("status=%d body=%s want=%s", w.Code, string(body), tc.want)
			}
		})
	}
}
