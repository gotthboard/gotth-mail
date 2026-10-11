package httpui

import (
	"context"
	"forgejo/gotthboard/gotth-mail/internal/admin"
	"forgejo/gotthboard/gotth-mail/internal/audit"
	"forgejo/gotthboard/gotth-mail/internal/authz"
	"forgejo/gotthboard/gotth-mail/internal/extensionsadmin"
	"forgejo/gotthboard/gotth-mail/internal/identity"
	"forgejo/gotthboard/gotth-mail/internal/store"
	"forgejo/gotthboard/gotth-mail/internal/testpg"
	"golang.org/x/net/html"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestExtensionDetailIntegratedRoute(t *testing.T) {
	db := testpg.DB(t, store.MigrateSQL)
	check := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatalf("fixture type=%T", err)
		}
	}
	const id = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	const alias = "{aaaa-aaaa-aaaa-4aaa-8aaa-aaaa-aaaa-aaaa}"
	ids := identity.NewService("example.test")
	check(ids.AddTokenWithScopes("integrated-owner", "api_token", "integrated-token", "ops:admin:"+alias))
	runtime := &targetUIRuntime{}
	svc, err := extensionsadmin.NewService(db, []byte(strings.Repeat("k", 32)), runtime)
	check(err)
	_, err = svc.Install(context.Background(), audit.ActorRef{Type: "local_admin", ID: "fixture"}, extensionsadmin.InstallRequest{InstanceID: id, ExtensionID: "notification.integrated", Repository: "https://github.com/gotthboard/gotth-extension-integrated", ArtifactPin: "sha256:" + strings.Repeat("1", 64), ManifestDigest: strings.Repeat("2", 64), GrantDigest: strings.Repeat("3", 64), SessionDigest: strings.Repeat("4", 64), Metadata: extensionsadmin.Metadata{Schema: extensionsadmin.MetadataSchema, Fields: []extensionsadmin.Field{{Name: "config.text", Label: "Text", Kind: extensionsadmin.FieldString}}}})
	check(err)
	h := HandlerWithAdminIdentitySessionsAndExtensions(admin.NewStore(), ids, authz.StaticAuthorizer{}, nil, time.Now, svc)
	request := func(method, path string, v url.Values, auth bool) *httptest.ResponseRecorder {
		token := ""
		if auth {
			token = "Bearer integrated-token"
		}
		r := formReq(method, path, v, token)
		r.Header.Set("HX-Request", "true")
		r.Header.Set("HX-History-Restore-Request", "true")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	path := extensionDetailActionURL(alias, "dark") + "&theme=light&PRIVATE=canary"
	before := targetUISnapshot(t, db)
	get := request("GET", path, nil, true)
	if get.Code != 200 || get.Header().Get("Cache-Control") != "private, no-store" || get.Header().Get("Content-Security-Policy") == "" || !strings.HasPrefix(strings.ToLower(get.Body.String()), "<!doctype html>") || !strings.Contains(get.Body.String(), "data-theme=\"dark\"") {
		t.Error("actual detail lacks full themed external document/privacy headers")
	}
	body := get.Body.String()
	if strings.Contains(body, "<style") || strings.Contains(body, "<script") || strings.Contains(body, "PRIVATE") || !strings.Contains(body, "/admin/extensions/assets/detail.css") {
		t.Error("unsafe/inline/nonexternal document")
	}
	for _, section := range []string{"overview", "configuration", "secrets", "permissions", "health", "audit", "versions", "rollback"} {
		if !strings.Contains(body, "id=\""+section+"\"") {
			t.Error("missing section", section)
		}
	}
	root, err := html.Parse(strings.NewReader(body))
	check(err)
	walkUpdateHTML(root, func(n *html.Node) {
		if n.Data == "form" && updateAttr(n, "action") != extensionDetailActionURL(alias, "dark") {
			t.Error("form lost raw route/theme")
		}
		if n.Data == "a" {
			href := updateAttr(n, "href")
			if strings.Contains(href, "/audit") && href != "/admin/extensions/"+id+"/audit" {
				t.Error("audit canonical contract changed")
			}
		}
	})
	for _, theme := range []string{"system", "light", "dark"} {
		if !strings.Contains(body, extensionDetailActionURL(alias, theme)) {
			t.Error("missing raw-alias theme link")
		}
	}
	if !reflect.DeepEqual(before, targetUISnapshot(t, db)) || runtime.calls != 0 {
		t.Fatal("GET mutated durable/runtime state")
	}
	preview := request("POST", path, url.Values{"action": {"configure-preview"}, "field.config.text": {"submitted-<script>"}, "theme": {"light"}}, true)
	if preview.Code != 200 || !strings.Contains(preview.Body.String(), "data-theme=\"dark\"") || !strings.Contains(preview.Body.String(), "theme navigation reloads stored state") {
		t.Error("POST query theme/projection navigation warning missing")
	}
	_, v, _ := updateForm(t, preview.Body.String(), "configure-apply")
	if v.Get("field.config.text") != "submitted-<script>" {
		t.Error("epilogue replaced configure Preview Fields")
	}
	before = targetUISnapshot(t, db)
	v.Set("confirmation", "wrong")
	denied := request("POST", path, v, true)
	if denied.Code != 200 || !strings.Contains(denied.Body.String(), "role=\"alert\"") || !reflect.DeepEqual(before, targetUISnapshot(t, db)) {
		t.Error("denial compatibility/restoration failed")
	}
	_, restored, _ := updateForm(t, denied.Body.String(), "configure-preview")
	if restored.Get("field.config.text") != "" {
		t.Error("error failed restoring stored Fields")
	}
	unauthorized := request("GET", path, nil, false)
	if unauthorized.Code != 401 || unauthorized.Header().Get("Content-Security-Policy") == "" {
		t.Error("error entry privacy absent")
	}
	// Unsupported persisted field is a read fixture, not new write-validation permission.
	_, err = db.Exec("UPDATE extension_instances SET metadata_json=jsonb_set(metadata_json,'{fields,0,kind}','\"unknown\"') WHERE instance_id=$1", id)
	check(err)
	before = targetUISnapshot(t, db)
	bad := request("GET", path, nil, true)
	// Approved policy change: decodable invalid metadata gets recovery, not blanket500.
	if bad.Code != 200 || strings.Contains(bad.Body.String(), `name="field.`) || !strings.Contains(bad.Body.String(), "Extension recovery — invalid configuration metadata") || !reflect.DeepEqual(before, targetUISnapshot(t, db)) {
		t.Error("unknown field did not render metadata-independent recovery")
	}
}

func TestExtensionDetailDocument(t *testing.T) {
	for _, theme := range []string{"system", "light", "dark", "unknown"} {
		view := extensionPageView{Item: extensionsadmin.Instance{ExtensionID: "name<script>", Enabled: true}, ActionURL: extensionDetailActionURL("{alias}", theme), Fields: []extensionFieldView{{Name: "text", Kind: "string", Value: "submitted"}}, Preview: extensionsadmin.Preview{Operation: "configure", ID: "reviewed", Confirmation: "confirm"}}
		var out strings.Builder
		if err := extensionDetailDocument(view, "{alias}", theme).Render(context.Background(), &out); err != nil {
			t.Fatal(err)
		}
		body := out.String()
		if !strings.HasPrefix(strings.ToLower(body), "<!doctype html>") || !strings.Contains(body, "data-theme=\""+inventoryTheme(theme)+"\"") || strings.Contains(body, "<style") || strings.Contains(body, "<script") || !strings.Contains(body, "name&lt;script&gt;") {
			t.Fatal("shell contract")
		}
		for _, id := range []string{"overview", "configuration", "secrets", "permissions", "health", "audit", "versions", "rollback"} {
			if strings.Count(body, "id=\""+id+"\"") != 1 {
				t.Fatal("section contract")
			}
		}
		_, v, _ := updateForm(t, body, "configure-apply")
		if v.Get("field.text") != "submitted" {
			t.Fatal("shell discarded Fields")
		}
		if !strings.Contains(body, "Recover / revalidate") || !strings.Contains(body, "value=\"disable\"") {
			t.Fatal("enabled lifecycle controls absent")
		}
		view.Fields[0].Kind = "unknown"
		w := httptest.NewRecorder()
		err := writeExtensionDetailComponent(w, httptest.NewRequest("GET", "/", nil), extensionDetailDocument(view, "{alias}", theme))
		if err == nil || w.Code != 500 || strings.Contains(w.Body.String(), "<html") {
			t.Fatal("shell leaked partial unknown-kind document")
		}
	}
}
