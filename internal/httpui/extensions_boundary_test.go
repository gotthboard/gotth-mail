package httpui

import (
	"context"
	"forgejo/gotthboard/gotth-mail/internal/admin"
	"forgejo/gotthboard/gotth-mail/internal/audit"
	"forgejo/gotthboard/gotth-mail/internal/authn"
	"forgejo/gotthboard/gotth-mail/internal/authz"
	"forgejo/gotthboard/gotth-mail/internal/extensionsadmin"
	"forgejo/gotthboard/gotth-mail/internal/identity"
	"forgejo/gotthboard/gotth-mail/internal/store"
	"forgejo/gotthboard/gotth-mail/internal/testpg"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestInstanceBoundaryUI(t *testing.T) {
	db := testpg.DB(t, store.MigrateSQL)
	check := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatalf("fixture type=%T", err)
		}
	}
	ids := identity.NewService("example.test")
	check(ids.AddTokenWithScopes("boundary", "api_token", "boundary-fixture", "ops:admin"))
	const id = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	check(ids.AddTokenWithScopes("narrow", "api_token", "boundary-narrow", "ops:admin:"+id))
	runtime := &targetUIRuntime{}
	svc, err := extensionsadmin.NewService(db, []byte(strings.Repeat("k", 32)), runtime)
	check(err)
	_, err = svc.Install(context.Background(), audit.ActorRef{Type: "local_admin", ID: "fixture"}, extensionsadmin.InstallRequest{InstanceID: id, ExtensionID: "notification.boundary", Repository: "https://github.com/gotthboard/gotth-extension-target", ArtifactPin: "sha256:" + strings.Repeat("1", 64), ManifestDigest: strings.Repeat("2", 64), GrantDigest: strings.Repeat("3", 64), SessionDigest: strings.Repeat("4", 64), Metadata: extensionsadmin.Metadata{Schema: extensionsadmin.MetadataSchema}})
	check(err)
	now := time.Now()
	const csrf = "boundary-csrf"
	const sid = "boundary-session"
	// Existing bound-session fixture isolates route/CSRF ordering, not durable login.
	sessions := uiSessionStore{bound: authn.BoundSession{Session: authn.Session{ID: sid, IdentityRefID: "boundary", CreatedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour), CSRFSecretHash: csrfHash(csrf)}, Mailbox: "admin@example.test", Roles: []authz.RoleAssignment{{Role: authz.RoleGlobalAdmin}}}}
	h := HandlerWithAdminIdentitySessionsAndExtensions(admin.NewStore(), ids, authz.StaticAuthorizer{}, sessions, func() time.Time { return now }, svc)
	request := func(method, target, auth string, cookie bool, form url.Values) *httptest.ResponseRecorder {
		r := formReq(method, "/admin/extensions/"+target, form, auth)
		if cookie {
			r.AddCookie(&http.Cookie{Name: "gotth_mail_session", Value: sid})
			r.AddCookie(&http.Cookie{Name: "gotth_mail_csrf", Value: csrf})
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	for _, method := range []string{"GET", "POST"} {
		t.Run(method, func(t *testing.T) {
			before := targetUISnapshot(t, db)
			form := url.Values{"action": {"test"}, "csrf_token": {csrf}}
			for _, target := range []string{strings.Repeat("a", 42), strings.Repeat("a", 65536), "invalid", "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"} {
				want := 400
				if strings.HasPrefix(target, "bbbb") {
					want = 404
				}
				for _, cookie := range []bool{false, true} {
					auth := "Bearer boundary-fixture"
					if cookie {
						auth = ""
					}
					w := request(method, target, auth, cookie, form)
					if w.Code != want {
						t.Errorf("initial status=%d want=%d", w.Code, want)
					}
				}
			}
			if request(method, strings.Repeat("a", 42), "", false, form).Code != 401 || request(method, strings.Repeat("a", 42), "Bearer boundary-narrow", false, form).Code != 403 || request(method, strings.Repeat("a", 42), "Bearer invalid", true, form).Code != 401 {
				t.Error("UI auth precedence")
			}
			if method == "POST" {
				form.Set("csrf_token", "wrong")
				if request(method, strings.Repeat("a", 42), "", true, form).Code != 403 {
					t.Error("cookie CSRF precedence")
				}
				form.Del("csrf_token")
				if request(method, strings.Repeat("a", 42), "Bearer boundary-fixture", false, form).Code != 400 {
					t.Error("bearer acquired CSRF gate")
				}
			}
			if !reflect.DeepEqual(before, targetUISnapshot(t, db)) || runtime.calls != 0 {
				t.Error("initial denial side effect")
			}
		})
	}
	for _, alias := range []string{"{aaaaaaaa-aaaa-4aaa-8aaa-aaaa-aaaa-aaaa}", "{aaaa-aaaa-aaaa-4aaa-8aaa-aaaa-aaaa-aaaa}"} {
		if request("GET", alias, "Bearer boundary-fixture", false, nil).Code != 200 {
			t.Error("UI native alias rejected")
		}
		if request("GET", alias, "Bearer boundary-narrow", false, nil).Code != 403 {
			t.Error("raw route scope normalized")
		}
	}
	r := httptest.NewRequest("POST", "/admin/extensions/"+strings.Repeat("a", 42), strings.NewReader("x=%zz"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	before := targetUISnapshot(t, db)
	h.ServeHTTP(w, r)
	if w.Code != 400 || !strings.Contains(w.Body.String(), "invalid extension form") || !reflect.DeepEqual(before, targetUISnapshot(t, db)) {
		t.Error("form parsing before auth changed")
	}
}
