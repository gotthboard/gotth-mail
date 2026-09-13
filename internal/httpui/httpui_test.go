package httpui

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"forgejo/gotthboard/gotth-mail/internal/admin"
	"forgejo/gotthboard/gotth-mail/internal/authz"
	"forgejo/gotthboard/gotth-mail/internal/identity"
)

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
