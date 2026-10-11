package httpui

import (
	"context"
	"encoding/json"
	"forgejo/gotthboard/gotth-mail/internal/admin"
	"forgejo/gotthboard/gotth-mail/internal/audit"
	"forgejo/gotthboard/gotth-mail/internal/authn"
	"forgejo/gotthboard/gotth-mail/internal/authz"
	"forgejo/gotthboard/gotth-mail/internal/identity"
	"forgejo/gotthboard/gotth-mail/internal/store"
	"forgejo/gotthboard/gotth-mail/internal/testpg"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	"forgejo/gotthboard/gotth-mail/internal/extensionsadmin"
	"golang.org/x/net/html"
)

func TestExtensionConfigurationActionURL(t *testing.T) {
	for _, id := range []string{"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", "{aaaa-aaaa-aaaa-4aaa-8aaa-aaaa-aaaa-aaaa}", "A?x=#/@evil"} {
		got := extensionDetailActionURL(id, "dark&action=disable")
		u, err := url.Parse(got)
		if err != nil || u.Host != "" || u.Fragment != "" || u.Path != "/admin/extensions/"+id || u.RawQuery != "theme=system" {
			t.Fatal("closed authorized spelling lost")
		}
	}
	if got := extensionDetailActionURL("abc", "dark"); got != "/admin/extensions/abc?theme=dark" {
		t.Fatal("normalized theme lost")
	}
}

func TestExtensionConfigurationComponent(t *testing.T) {
	for _, configured := range []bool{false, true} {
		t.Run(map[bool]string{false: "initial", true: "configured"}[configured], func(t *testing.T) {
			item := extensionsadmin.Instance{Metadata: extensionsadmin.Metadata{Fields: []extensionsadmin.Field{
				{Name: "config.text", Label: "Text <label>", Kind: extensionsadmin.FieldString, Required: true},
				{Name: "config.number", Label: "Number", Kind: extensionsadmin.FieldInteger},
				{Name: "config.flag", Label: "Flag", Kind: extensionsadmin.FieldBoolean, Required: true},
				{Name: "config.off", Label: "Off", Kind: extensionsadmin.FieldBoolean},
				{Name: "config.mode", Label: "Mode", Kind: extensionsadmin.FieldEnum, Options: []string{"first", "second & final"}},
				{Name: "config.default", Label: "Default", Kind: extensionsadmin.FieldString, Required: true, Default: "NEVER-INSERT"},
				{Name: "config.key", Label: "Secret", Kind: extensionsadmin.FieldSecret, Required: true},
			}}, Configuration: map[string]any{"config.text": " <hostile> ", "config.flag": true, "config.mode": "second & final"}, Secrets: []extensionsadmin.SecretStatus{{Slot: "config.key", Configured: configured}}}
			view := extensionPageView{Fields: extensionFields(item, nil), CSRF: "csrf-fixture", ActionURL: extensionDetailActionURL("{alias}", "dark"), Preview: extensionsadmin.Preview{ID: "preview-fixture", Operation: "configure", Confirmation: "confirm-fixture"}}
			view.Fields[len(view.Fields)-1].Value = "PRIVATE-password-canary"
			w := httptest.NewRecorder()
			if err := writeExtensionDetailComponent(w, httptest.NewRequest("GET", "/", nil), extensionConfigurationForms(view)); err != nil {
				t.Fatal(err)
			}
			body := w.Body.String()
			if strings.Contains(body, "PRIVATE-password-canary") || strings.Contains(body, "NEVER-INSERT") || strings.Contains(body, "<hostile>") {
				t.Fatal("unsafe field/default reflection")
			}
			preview, _, _ := updateForm(t, body, "configure-preview")
			apply, _, _ := updateForm(t, body, "configure-apply")
			// updateForm parses each call independently; compare ownership in one DOM below.
			root, err := html.Parse(strings.NewReader(body))
			if err != nil {
				t.Fatal(err)
			}
			var forms []*html.Node
			walkUpdateHTML(root, func(n *html.Node) {
				if n.Data == "form" {
					forms = append(forms, n)
				}
			})
			if len(forms) != 2 || forms[0].Parent != forms[1].Parent {
				t.Fatal("forms are not sibling nodes")
			}
			if updateAttr(preview, "method") != "post" || updateAttr(apply, "action") != view.ActionURL || updateAttr(preview, "action") != view.ActionURL {
				t.Fatal("forms are not independent native siblings")
			}
			pv, _ := configurationActionForm(t, body, "configure-preview")
			av, confirmation := configurationForm(t, body)
			if confirmation != "confirm-fixture" || pv.Has("preview_id") || pv.Has("confirmation") || av.Get("preview_id") != "preview-fixture" {
				t.Fatal("confirmation ownership")
			}
			for _, v := range []url.Values{pv, av} {
				if v.Get("csrf_token") != "csrf-fixture" || v.Get("field.config.text") != "<hostile>" || v.Get("field.config.mode") != "second & final" || !v.Has("field.config.flag") || v.Has("field.config.off") || v.Get("field.config.number") != "" || v.Get("field.config.default") != "" || v.Get("field.config.key") != "" {
					t.Fatal("projected successful controls changed")
				}
			}
			has := func(n *html.Node, key string) bool {
				for _, a := range n.Attr {
					if a.Key == key {
						return true
					}
				}
				return false
			}
			for _, form := range []*html.Node{preview, apply} {
				walkUpdateHTML(form, func(n *html.Node) {
					if n.Data == "input" && updateAttr(n, "name") == "field.config.key" {
						if updateAttr(n, "type") != "password" || updateAttr(n, "autocomplete") != "new-password" || has(n, "required") == configured {
							t.Error("secret requirement/blank contract")
						}
					}
					if updateAttr(n, "type") == "checkbox" && has(n, "required") {
						t.Error("boolean wrongly required")
					}
					if n.Data == "script" || n.Data == "hostile" || n.Data == "label" && updateAttr(n, "onclick") != "" {
						t.Error("injected markup")
					}
				})
			}
			view.Preview.Operation = "update"
			var b strings.Builder
			if err := extensionConfigurationForms(view).Render(context.Background(), &b); err != nil {
				t.Fatal(err)
			}
			if strings.Contains(b.String(), "configure-apply") || strings.Contains(b.String(), "preview-fixture") {
				t.Fatal("wrong operation exposed Apply")
			}
		})
	}
}

func TestExtensionConfigurationUnknownKind(t *testing.T) {
	w := httptest.NewRecorder()
	err := writeExtensionDetailComponent(w, httptest.NewRequest("GET", "/", nil), extensionConfigurationForms(extensionPageView{Fields: []extensionFieldView{{Name: "bad", Kind: "unknown"}}}))
	if err == nil || w.Code != 500 || strings.Contains(w.Body.String(), "configure-preview") {
		t.Fatal("unknown field produced partial successful form")
	}
}

// The new component is rendered only by this test, never a temporary product route.
// Its successful controls go through the unchanged real handler/service/SQL path.
func TestExtensionConfigurationComponentAliasRoundtrip(t *testing.T) {
	db := testpg.DB(t, store.MigrateSQL)
	check := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatalf("fixture error type=%T", err)
		}
	}
	ids := identity.NewService("example.test")
	const id = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	const alias = "{aaaa-aaaa-aaaa-4aaa-8aaa-aaaa-aaaa-aaaa}"
	check(ids.AddTokenWithScopes("alias-owner", "api_token", "alias-token", "ops:admin:"+alias))
	check(ids.AddTokenWithScopes("canonical-owner", "api_token", "canonical-token", "ops:admin:"+id))
	runtime := &targetUIRuntime{}
	svc, err := extensionsadmin.NewService(db, []byte(strings.Repeat("k", 32)), runtime)
	check(err)
	actor := audit.ActorRef{Type: "api_token", ID: "alias-owner"}
	item, err := svc.Install(context.Background(), audit.ActorRef{Type: "local_admin", ID: "fixture"}, extensionsadmin.InstallRequest{InstanceID: id, ExtensionID: "notification.alias", Repository: "https://github.com/gotthboard/gotth-extension-target", ArtifactPin: "sha256:" + strings.Repeat("1", 64), ManifestDigest: strings.Repeat("2", 64), GrantDigest: strings.Repeat("3", 64), SessionDigest: strings.Repeat("4", 64), SecretSlots: []string{"config.key"}, Metadata: extensionsadmin.Metadata{Schema: extensionsadmin.MetadataSchema, Fields: []extensionsadmin.Field{{Name: "config.text", Label: "Text", Kind: extensionsadmin.FieldString}, {Name: "config.key", Label: "Key", Kind: extensionsadmin.FieldSecret, Required: true}}}})
	check(err)
	h := HandlerWithAdminIdentitySessionsAndExtensions(admin.NewStore(), ids, authz.StaticAuthorizer{}, nil, time.Now, svc)
	actionURL := extensionDetailActionURL(alias, "dark")
	request := func(method, path, token string, v url.Values) *httptest.ResponseRecorder {
		r := formReq(method, path, v, "Bearer "+token)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	before := targetUISnapshot(t, db)
	if request("GET", actionURL, "alias-token", nil).Code != 200 || request("GET", actionURL, "canonical-token", nil).Code != 403 || request("GET", extensionDetailActionURL(id, "dark"), "alias-token", nil).Code != 403 {
		t.Fatal("raw route scope compatibility changed")
	}
	if !reflect.DeepEqual(before, targetUISnapshot(t, db)) || runtime.calls != 0 {
		t.Fatal("read/denial effects")
	}
	for _, phase := range []string{"initial", "retain", "rotate"} {
		t.Run(phase, func(t *testing.T) {
			item, err = svc.Get(context.Background(), id)
			check(err)
			input := extensionsadmin.ConfigureInput{Configuration: map[string]any{"config.text": "accepted-" + phase}, Secrets: map[string]string{}}
			if phase != "retain" {
				input.Secrets["config.key"] = "PRIVATE-key-" + phase
			}
			preview, err := svc.PreviewConfigure(context.Background(), actor, id, input)
			check(err)
			view := extensionPageView{Item: item, Fields: extensionFields(item, input.Configuration), Preview: preview, ActionURL: actionURL}
			var out strings.Builder
			check(extensionConfigurationForms(view).Render(context.Background(), &out))
			if strings.Contains(out.String(), "PRIVATE-key-") {
				t.Fatal("renderer received/reflected secret")
			}
			values, confirmation := configurationForm(t, out.String())
			values.Set("confirmation", confirmation)
			before := targetUISnapshot(t, db)
			denied := request("POST", actionURL, "canonical-token", values)
			if denied.Code != 403 || !reflect.DeepEqual(before, targetUISnapshot(t, db)) {
				t.Fatal("canonical-only scope acquired alias authority")
			}
			if phase != "retain" {
				values.Set("field.config.key", "wrong-key")
				denied = request("POST", actionURL, "alias-token", values)
				if denied.Code != 200 || !strings.Contains(denied.Body.String(), "extension confirmation rejected") || !reflect.DeepEqual(before, targetUISnapshot(t, db)) {
					t.Fatal("wrong rotation/initial re-entry admitted")
				}
				values.Set("field.config.key", input.Secrets["config.key"])
			}
			var oldSecret string
			check(db.QueryRow("SELECT COALESCE(jsonb_agg(to_jsonb(s))::text,'[]') FROM extension_secrets s WHERE instance_id=$1", id).Scan(&oldSecret))
			applied := request("POST", actionURL, "alias-token", values)
			if applied.Code != 200 || !strings.Contains(applied.Body.String(), "extension operation accepted") {
				t.Fatal("component controls rejected by unchanged handler")
			}
			got, err := svc.Get(context.Background(), id)
			check(err)
			if got.ConfigurationRev != item.ConfigurationRev+1 || got.Configuration["config.text"] != "accepted-"+phase || len(got.Secrets) != 1 || !got.Secrets[0].Configured || runtime.calls != 0 {
				t.Fatal("wrong service effects")
			}
			var nextSecret string
			check(db.QueryRow("SELECT COALESCE(jsonb_agg(to_jsonb(s))::text,'[]') FROM extension_secrets s WHERE instance_id=$1", id).Scan(&nextSecret))
			if (oldSecret == nextSecret) != (phase == "retain") {
				t.Fatal("secret retention/rotation mismatch")
			}
			after := targetUISnapshot(t, db)
			replay := request("POST", actionURL, "alias-token", values)
			if replay.Code != 200 || !strings.Contains(replay.Body.String(), "extension confirmation rejected") || !reflect.DeepEqual(after, targetUISnapshot(t, db)) {
				t.Fatal("preview replay changed state")
			}
		})
	}
}

func TestExtensionMetadataDefaultProjection(t *testing.T) {
	for _, n := range []string{"9007199254740991", "9007199254740992", "9007199254740993", "-9223372036854775808", "9223372036854775807"} {
		t.Run(n, func(t *testing.T) {
			item := extensionsadmin.Instance{Metadata: extensionsadmin.Metadata{Schema: extensionsadmin.MetadataSchema, Fields: []extensionsadmin.Field{{Name: "config.number", Label: "Number", Kind: extensionsadmin.FieldInteger, Required: true, Default: json.Number(n)}}}}
			fields := extensionFields(item, nil)
			if len(fields) != 1 || fields[0].Required || fields[0].Value != "" {
				t.Fatal("default auto-filled or required")
			}
			var body strings.Builder
			if err := extensionConfigurationForms(extensionPageView{Fields: fields, CSRF: "fixture", ActionURL: "/admin/extensions/id?theme=system"}).Render(context.Background(), &body); err != nil {
				t.Fatal(err)
			}
			if strings.Contains(body.String(), n) {
				t.Fatal("default reflected")
			}
			root, err := html.Parse(strings.NewReader(body.String()))
			if err != nil {
				t.Fatal(err)
			}
			count := 0
			walkUpdateHTML(root, func(node *html.Node) {
				if node.Data == "input" && updateAttr(node, "name") == "field.config.number" {
					count++
					if updateAttr(node, "type") != "number" || updateAttr(node, "value") != "" {
						t.Error("blank number projection changed")
					}
					for _, a := range node.Attr {
						if a.Key == "required" {
							t.Error("default-backed number required")
						}
					}
				}
			})
			if count != 1 {
				t.Fatal("number control cardinality")
			}
			r := httptest.NewRequest("POST", "/", nil)
			r.Form = url.Values{"field.config.number": {""}}
			input, err := extensionConfigurationInput(item, r)
			if err != nil || len(input.Configuration) != 0 {
				t.Fatal("blank default-backed input not omitted")
			}
			encoded, err := extensionsadmin.ValidateConfiguration(item.Metadata, input.Configuration, nil)
			if err != nil || string(encoded) != "{}" {
				t.Fatal("default inserted by validation")
			}
		})
	}
}

func TestExtensionMetadataReadStatusCompatibility(t *testing.T) {
	db := testpg.DB(t, store.MigrateSQL)
	runtime := &retentionRuntime{}
	svc, err := extensionsadmin.NewService(db, []byte(strings.Repeat("k", 32)), runtime)
	if err != nil {
		t.Fatal(err)
	}
	raw := "{\"schema\":\"gotth.mail.extension.config.v1\",\"fields\":[{\"name\":\"config.number\",\"label\":\"Number\",\"kind\":\"integer\",\"required\":true,\"min\":9007199254740993,\"max\":9007199254740993,\"default\":9007199254740993}]}"
	metadata, err := extensionsadmin.DecodeMetadata([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	id := "00000000-0000-4000-8000-000000009301"
	_, err = svc.Install(context.Background(), audit.ActorRef{Type: "local_admin", ID: "fixture"}, extensionsadmin.InstallRequest{InstanceID: id, ExtensionID: "precision.ui", Repository: "https://github.com/gotthboard/gotth-extension-precision", ArtifactPin: "sha256:" + strings.Repeat("1", 64), ManifestDigest: strings.Repeat("2", 64), GrantDigest: strings.Repeat("3", 64), SessionDigest: strings.Repeat("4", 64), Metadata: metadata})
	if err != nil {
		t.Fatal("SETUP install failed")
	}
	now := time.Now()
	sid, csrf := "precision-session", "precision-csrf"
	owner := authn.BoundSession{Session: authn.Session{ID: sid, IdentityRefID: "precision-admin", CreatedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour), CSRFSecretHash: csrfHash(csrf)}, Mailbox: "admin@example.test", Roles: []authz.RoleAssignment{{Role: authz.RoleGlobalAdmin}}}
	handler := HandlerWithAdminIdentitySessionsAndExtensions(admin.NewStore(), identity.NewService("example.test"), authz.StaticAuthorizer{}, uiSessionStore{bound: owner}, func() time.Time { return now }, svc)
	request := func(target string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("GET", "/admin/extensions/"+target, nil)
		withIdentityCookies(r, sid, csrf)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w
	}
	before := targetUISnapshot(t, db)
	w := request(id)
	if w.Code != 200 || strings.Contains(w.Body.String(), "9007199254740993") {
		t.Fatal("GET/default projection compatibility changed")
	}
	if request("00000000-0000-4000-8000-000000999999").Code != 404 {
		t.Fatal("missing GET status")
	}
	if !reflect.DeepEqual(before, targetUISnapshot(t, db)) {
		t.Fatal("GET changed rows")
	}
	// DIRECT DB malformed typed metadata setup; never a claimed admitted write.
	if _, err := db.Exec("UPDATE extension_instances SET metadata_json=$1::jsonb WHERE instance_id=$2", "{\"schema\":\"PRIVATE-metadata-marker\",\"fields\":\"wrong-type\"}", id); err != nil {
		t.Fatal("SETUP typed metadata fault failed")
	}
	before = targetUISnapshot(t, db)
	w = request(id)
	if w.Code != 400 || strings.Contains(w.Body.String(), "PRIVATE-metadata-marker") || strings.Contains(w.Body.String(), "wrong-type") {
		t.Fatal("sanitized GET decode failure changed")
	}
	if !reflect.DeepEqual(before, targetUISnapshot(t, db)) {
		t.Fatal("failed GET changed rows")
	}
	if runtime.starts != 0 {
		t.Fatal("GET started runtime")
	}
}
