package httpui

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	"forgejo/gotthboard/gotth-mail/internal/admin"
	"forgejo/gotthboard/gotth-mail/internal/audit"
	"forgejo/gotthboard/gotth-mail/internal/authn"
	"forgejo/gotthboard/gotth-mail/internal/authz"
	"forgejo/gotthboard/gotth-mail/internal/extensionsadmin"
	"forgejo/gotthboard/gotth-mail/internal/identity"
	"forgejo/gotthboard/gotth-mail/internal/store"
	"forgejo/gotthboard/gotth-mail/internal/testpg"
)

type recoveryRuntime struct {
	calls []string
	fail  bool
}

func (r *recoveryRuntime) Start(context.Context, extensionsadmin.Instance, map[string][]byte) error {
	r.calls = append(r.calls, "start")
	return nil
}
func (r *recoveryRuntime) Probe(context.Context, extensionsadmin.Instance) (extensionsadmin.Health, error) {
	r.calls = append(r.calls, "probe")
	if r.fail {
		return extensionsadmin.Health{}, errors.New("probe failed")
	}
	return extensionsadmin.Health{Healthy: true, Code: "extension.ready"}, nil
}
func (r *recoveryRuntime) AdmitRouting(context.Context, extensionsadmin.Instance) error {
	r.calls = append(r.calls, "admit")
	return nil
}
func (r *recoveryRuntime) RevokeRouting(context.Context, extensionsadmin.Instance) error {
	r.calls = append(r.calls, "revoke")
	return nil
}
func (r *recoveryRuntime) Stop(context.Context, extensionsadmin.Instance) error {
	r.calls = append(r.calls, "stop")
	return nil
}

func TestRecoveryUI(t *testing.T) {
	db := testpg.DB(t, store.MigrateSQL)
	runtime := &recoveryRuntime{}
	svc, err := extensionsadmin.NewService(db, []byte(strings.Repeat("k", 32)), runtime)
	if err != nil {
		t.Fatal(err)
	}
	id := "00000000-0000-4000-8000-000000000027"
	actor := audit.ActorRef{Type: "local_admin", ID: "fixture"}
	_, err = svc.Install(context.Background(), actor, extensionsadmin.InstallRequest{InstanceID: id, ExtensionID: "notification.recovery", Repository: "https://github.com/gotthboard/gotth-extension-recovery", ArtifactPin: "sha256:" + strings.Repeat("1", 64), ManifestDigest: strings.Repeat("2", 64), GrantDigest: strings.Repeat("3", 64), SessionDigest: strings.Repeat("4", 64), Metadata: extensionsadmin.Metadata{Schema: extensionsadmin.MetadataSchema}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Test(context.Background(), actor, id); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Enable(context.Background(), actor, id); err != nil {
		t.Fatal(err)
	}
	runtime.calls = nil
	now := time.Now()
	const sid = "recovery-session"
	const csrf = "recovery-csrf"
	bound := authn.BoundSession{Session: authn.Session{ID: sid, IdentityRefID: "admin", CreatedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour), CSRFSecretHash: csrfHash(csrf)}, Mailbox: "admin@example.test", Roles: []authz.RoleAssignment{{Role: authz.RoleGlobalAdmin}}}
	handler := func(b authn.BoundSession) http.Handler {
		return HandlerWithAdminIdentitySessionsAndExtensions(admin.NewStore(), identity.NewService("example.test"), authz.StaticAuthorizer{}, uiSessionStore{bound: b}, func() time.Time { return now }, svc)
	}
	request := func(method, token string, b authn.BoundSession) *httptest.ResponseRecorder {
		req := formReq(method, "/admin/extensions/"+id, url.Values{"action": {"enable"}, "csrf_token": {token}}, "")
		withIdentityCookies(req, sid, csrf)
		res := httptest.NewRecorder()
		handler(b).ServeHTTP(res, req)
		return res
	}
	for _, state := range []string{"ready", "restart"} {
		if state == "restart" {
			if err := svc.ReconcileRestart(context.Background()); err != nil {
				t.Fatal(err)
			}
		}
		res := request(http.MethodGet, "", bound)
		if res.Code != 200 || !strings.Contains(res.Body.String(), ">Recover / revalidate</button>") || !strings.Contains(res.Body.String(), `value="disable">Disable</button>`) || !strings.Contains(res.Body.String(), `aria-describedby="extension-recovery-help"`) {
			t.Errorf("%s missing accessible recovery/disable form: %s", state, res.Body.String())
		}
		if len(runtime.calls) != 0 {
			t.Fatal("GET started runtime")
		}
	}
	for _, token := range []string{"", "wrong"} {
		res := request(http.MethodPost, token, bound)
		if res.Code != 403 || len(runtime.calls) != 0 {
			t.Fatalf("CSRF denial failed: %d %v", res.Code, runtime.calls)
		}
	}
	nonadmin := bound
	nonadmin.Roles = nil
	if res := request(http.MethodPost, csrf, nonadmin); res.Code != 403 || len(runtime.calls) != 0 {
		t.Fatalf("role denial failed: %d", res.Code)
	}
	// Stale tested revision is visible failure; no new execution authority.
	if _, err := db.Exec("UPDATE extension_instances SET tested_revision=NULL"); err != nil {
		t.Fatal(err)
	}
	res := request(http.MethodPost, csrf, bound)
	if strings.Contains(res.Body.String(), "extension operation accepted") || strings.Contains(strings.Join(runtime.calls, ","), "start") {
		t.Fatal("stale recovery admitted")
	}
	if _, err := db.Exec("UPDATE extension_instances SET tested_revision=configuration_revision"); err != nil {
		t.Fatal(err)
	}
	runtime.calls = nil
	runtime.fail = true
	res = request(http.MethodPost, csrf, bound)
	if strings.Contains(res.Body.String(), "extension operation accepted") || !reflect.DeepEqual(runtime.calls, []string{"start", "probe", "revoke", "stop"}) {
		t.Fatalf("failed recovery misreported: %v", runtime.calls)
	}
	runtime.calls = nil
	runtime.fail = false
	res = request(http.MethodPost, csrf, bound)
	if res.Code != 200 || !strings.Contains(res.Body.String(), "extension operation accepted") || !reflect.DeepEqual(runtime.calls, []string{"start", "probe", "admit"}) {
		t.Fatalf("authorized HTML recovery failed: %d %v", res.Code, runtime.calls)
	}
	got, err := svc.Get(context.Background(), id)
	if err != nil || !got.Routed {
		t.Fatal("recovery not committed", err)
	}
}
