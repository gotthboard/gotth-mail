package httpui

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"forgejo/linus/gophermailforge/internal/admin"
	"forgejo/linus/gophermailforge/internal/authz"
	"forgejo/linus/gophermailforge/internal/identity"
)

func TestMailAdminCRUDScreensRenderAndMutate(t *testing.T) {
	s := admin.NewStore()
	h := HandlerWithAdmin(s)
	form := url.Values{"name": {"Example.Test"}, "enabled": {"on"}}
	req := httptest.NewRequest(http.MethodPost, "/admin/domains", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("domain status=%d", w.Code)
	}
	form = url.Values{"address": {"Smoke@Example.Test"}, "enabled": {"on"}}
	req = httptest.NewRequest(http.MethodPost, "/admin/users", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)
	form = url.Values{"address": {"Alias@Example.Test"}, "targets": {"Smoke@Example.Test"}, "enabled": {"on"}}
	req = httptest.NewRequest(http.MethodPost, "/admin/aliases", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)
	req = httptest.NewRequest(http.MethodGet, "/", nil)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)
	body, _ := io.ReadAll(w.Result().Body)
	text := string(body)
	for _, want := range []string{"Domain CRUD", "User CRUD", "Alias CRUD", "example.test", "smoke@example.test", "alias@example.test", "OIDC/Auth status", "Authentik role/group mapping", "SCIM status/test", "App-password list/create/revoke", "Permission simulator UI", "Audit UI/search/export", "Backup/restore verification", "Snapshot/rollback guidance", "Mailu import preview/apply", "Abuse/rate-limit dashboard", "Bulk admin workflows", "Doctor screens", "DNS/DKIM screens", "Plugin status/config screens", "Lookup debugger UI"} {
		if !strings.Contains(text, want) {
			t.Fatalf("admin UI missing %q in %s", want, text)
		}
	}
}

func TestIdentityUIScreensUseServicePaths(t *testing.T) {
	ids := identity.NewService("example.test")
	_, err := ids.CreateOrReplaceUser(nil, authz.Actor{Type: "local_admin", ID: "seed"}, identity.Mailbox{Email: "user@example.test", Active: true}, "mail-password")
	if err != nil {
		t.Fatal(err)
	}
	ids.Secret = func() (string, error) { return "ui-secret-token", nil }
	h := HandlerWithAdminAndIdentity(admin.NewStore(), ids, authz.StaticAuthorizer{})
	form := url.Values{"mailbox": {"user@example.test"}, "label": {"phone"}}
	req := httptest.NewRequest(http.MethodPost, "/identity/app-passwords", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	body, _ := io.ReadAll(w.Result().Body)
	text := string(body)
	if w.Code != http.StatusOK || !strings.Contains(text, "secret_once=ui-secret-token") || !strings.Contains(text, "phone") {
		t.Fatalf("status=%d body=%s", w.Code, text)
	}
	if len(ids.Audit.Events) == 0 || ids.Audit.Events[len(ids.Audit.Events)-1].Action != "app_password.create" {
		t.Fatalf("missing audit %#v", ids.Audit.Events)
	}
	form = url.Values{"actor_type": {"local_admin"}, "actor_id": {"ui"}, "action": {"status:read"}, "resource_type": {"system"}, "resource_id": {"self"}}
	req = httptest.NewRequest(http.MethodPost, "/identity/simulator", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)
	body, _ = io.ReadAll(w.Result().Body)
	if !strings.Contains(string(body), "local admin may administer all resources") {
		t.Fatalf("simulator body=%s", string(body))
	}
}

func TestSCIMUITestActionProvisionsUser(t *testing.T) {
	ids := identity.NewService("example.test")
	h := HandlerWithAdminAndIdentity(admin.NewStore(), ids, authz.StaticAuthorizer{})
	form := url.Values{"userName": {"ui@example.test"}, "displayName": {"UI User"}, "password": {"mail-password"}}
	req := httptest.NewRequest(http.MethodPost, "/identity/scim-test", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	body, _ := io.ReadAll(w.Result().Body)
	if w.Code != http.StatusOK || !strings.Contains(string(body), "SCIM test user provisioned: ui@example.test") || !strings.Contains(string(body), "UI User") {
		t.Fatalf("status=%d body=%s", w.Code, string(body))
	}
	if _, ok := ids.GetUser("ui@example.test"); !ok {
		t.Fatal("SCIM UI did not provision user")
	}
}

func TestV3OperatorUIFormsExecute(t *testing.T) {
	h := HandlerWithAdminAndIdentity(admin.NewStore(), identity.NewService("example.test"), authz.StaticAuthorizer{})
	cases := []struct {
		path string
		form url.Values
		want string
	}{
		{"/ops/backup-verify", url.Values{"artifact_ref": {"ui-backup"}}, "backup verification status=verified"},
		{"/ops/mailu-preview", url.Values{"source": {`[{"Type":"domain","ID":"example.test"}]`}}, "mailu preview created:"},
		{"/ops/bulk-preview", url.Values{"operation": {"disable-users"}, "items": {"user@example.test"}}, "bulk preview created:"},
	}
	for _, tc := range cases {
		t.Run(tc.path, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, tc.path, strings.NewReader(tc.form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			w := httptest.NewRecorder()
			h.ServeHTTP(w, req)
			body, _ := io.ReadAll(w.Result().Body)
			if w.Code != http.StatusOK || !strings.Contains(string(body), tc.want) {
				t.Fatalf("status=%d body=%s want=%s", w.Code, string(body), tc.want)
			}
		})
	}
}
