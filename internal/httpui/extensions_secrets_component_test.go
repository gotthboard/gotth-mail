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

func TestExtensionSecretsComponent(t *testing.T) {
	for _, populated := range []bool{false, true} {
		t.Run(map[bool]string{false: "empty", true: "statuses"}[populated], func(t *testing.T) {
			view := extensionPageView{CSRF: "csrf-fixture", ActionURL: extensionDetailActionURL("{alias}", "dark"), Preview: extensionsadmin.Preview{Operation: "delete_secrets", ID: "preview-fixture", Confirmation: "confirm-fixture"}}
			if populated {
				view.Item.Secrets = []extensionsadmin.SecretStatus{{Slot: "key.<script>", Configured: true}, {Slot: "other.key", Configured: false}}
			}
			view.Item.Configuration = map[string]any{"PRIVATE": "PRIVATE-secret-value"}
			var out strings.Builder
			if err := extensionSecretForms(view).Render(context.Background(), &out); err != nil {
				t.Fatal(err)
			}
			body := out.String()
			if strings.Contains(body, "PRIVATE-secret-value") || strings.Contains(body, "<script>") {
				t.Fatal("unsafe secret/status reflection")
			}
			for _, text := range []string{"all stored secrets", "including retained slots", "does not prove", "Secret deletion confirmation", "confirm-fixture"} {
				if !strings.Contains(body, text) {
					t.Error("missing truthful scope/confirmation")
				}
			}
			if populated && (!strings.Contains(body, "key.&lt;script&gt;") || !strings.Contains(body, "Not configured") || !strings.Contains(body, "Configured")) {
				t.Error("status projection missing")
			}
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
				t.Fatal("not sibling forms")
			}
			preview, pv, _ := updateForm(t, body, "secrets-delete-preview")
			apply, av, _ := updateForm(t, body, "secrets-delete-apply")
			if !reflect.DeepEqual(pv, url.Values{"csrf_token": {"csrf-fixture"}, "action": {"secrets-delete-preview"}}) || !reflect.DeepEqual(av, url.Values{"csrf_token": {"csrf-fixture"}, "preview_id": {"preview-fixture"}, "confirmation": {""}, "action": {"secrets-delete-apply"}}) {
				t.Fatal("form ownership/control contract")
			}
			for _, f := range []*html.Node{preview, apply} {
				if updateAttr(f, "action") != view.ActionURL {
					t.Error("action changed")
				}
			}
			required := 0
			walkUpdateHTML(preview, func(n *html.Node) {
				for _, a := range n.Attr {
					if a.Key == "required" {
						t.Error("blank Apply can obstruct Preview")
					}
				}
			})
			walkUpdateHTML(apply, func(n *html.Node) {
				for _, a := range n.Attr {
					if a.Key == "checked" || a.Key == "disabled" {
						t.Error("invented consent/authority")
					}
					if a.Key == "required" {
						required++
						if updateAttr(n, "name") != "confirmation" || n.Parent.Data != "label" {
							t.Error("required confirmation label missing")
						}
					}
				}
			})
			if required != 1 {
				t.Error("exactly one required confirmation expected")
			}
			view.Preview.Operation = "uninstall"
			out.Reset()
			if err := extensionSecretForms(view).Render(context.Background(), &out); err != nil {
				t.Fatal(err)
			}
			if strings.Contains(out.String(), "secrets-delete-apply") || strings.Contains(out.String(), "preview-fixture") {
				t.Fatal("wrong preview exposed Apply")
			}
			updateForm(t, out.String(), "secrets-delete-preview")
		})
	}
}

func TestExtensionSecretsComponentRetainedDeletion(t *testing.T) {
	db := testpg.DB(t, store.MigrateSQL)
	check := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatalf("fixture type=%T", err)
		}
	}
	ids := identity.NewService("example.test")
	check(ids.AddTokenWithScopes("delete-component", "api_token", "delete-component-token", "ops:admin"))
	actor := audit.ActorRef{Type: "api_token", ID: "delete-component"}
	runtime := &targetUIRuntime{}
	svc, err := extensionsadmin.NewService(db, []byte(strings.Repeat("k", 32)), runtime)
	check(err)
	const id = "00000000-0000-4000-8000-000000000092"
	const other = "00000000-0000-4000-8000-000000000093"
	for _, x := range []struct{ id, name string }{{id, "chosen"}, {other, "survivor"}} {
		_, err := svc.Install(context.Background(), audit.ActorRef{Type: "local_admin", ID: "fixture"}, extensionsadmin.InstallRequest{InstanceID: x.id, ExtensionID: "notification." + x.name, Repository: "https://github.com/gotthboard/gotth-extension-secret", ArtifactPin: "sha256:" + strings.Repeat("1", 64), ManifestDigest: strings.Repeat("2", 64), GrantDigest: strings.Repeat("3", 64), SessionDigest: strings.Repeat("4", 64), SecretSlots: []string{"retained.key", "current.key"}, Metadata: extensionsadmin.Metadata{Schema: extensionsadmin.MetadataSchema}})
		check(err)
		input := extensionsadmin.ConfigureInput{Secrets: map[string]string{"retained.key": "PRIVATE-retained-value", "current.key": "PRIVATE-current-value"}}
		p, err := svc.PreviewConfigure(context.Background(), actor, x.id, input)
		check(err)
		_, err = svc.ApplyConfigure(context.Background(), actor, x.id, p.ID, p.Confirmation, input)
		check(err)
	}
	// Existing retained-slot fixture seam: current list empty, encrypted rows retained.
	_, err = db.Exec("UPDATE extension_instances SET secret_slots_json='[]',tested_revision=configuration_revision,health_code='extension.ready' WHERE instance_id=$1", id)
	check(err)
	item, err := svc.Get(context.Background(), id)
	check(err)
	if len(item.Secrets) != 0 {
		t.Fatal("fixture must expose empty current status list")
	}
	var retained int
	check(db.QueryRow("SELECT count(*) FROM extension_secrets WHERE instance_id=$1", id).Scan(&retained))
	if retained != 2 {
		t.Fatal("retained-row fixture absent")
	}
	survivor := func() string {
		var s string
		check(db.QueryRow("SELECT to_jsonb(i)::text || COALESCE((SELECT jsonb_agg(to_jsonb(s))::text FROM extension_secrets s WHERE s.instance_id=i.instance_id),'[]') FROM extension_instances i WHERE instance_id=$1", other).Scan(&s))
		return s
	}
	otherBefore := survivor()
	p, err := svc.PreviewDeleteSecrets(context.Background(), actor, id)
	check(err)
	var out strings.Builder
	check(extensionSecretForms(extensionPageView{Item: item, Preview: p, ActionURL: extensionDetailActionURL(id, "system")}).Render(context.Background(), &out))
	_, v, confirmation := updateForm(t, out.String(), "secrets-delete-apply")
	h := HandlerWithAdminIdentitySessionsAndExtensions(admin.NewStore(), ids, authz.StaticAuthorizer{}, nil, time.Now, svc)
	request := func() *httptest.ResponseRecorder {
		r := formReq("POST", extensionDetailActionURL(id, "system"), v, "Bearer delete-component-token")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	before := targetUISnapshot(t, db)
	v.Set("confirmation", "wrong")
	denied := request()
	if denied.Code != 200 || !strings.Contains(denied.Body.String(), "extension confirmation rejected") || !reflect.DeepEqual(before, targetUISnapshot(t, db)) {
		t.Fatal("denial changed state")
	}
	v.Set("confirmation", confirmation)
	applied := request()
	if applied.Code != 200 || !strings.Contains(applied.Body.String(), "extension operation accepted") {
		t.Fatal("delete rejected")
	}
	got, err := svc.Get(context.Background(), id)
	check(err)
	want := item
	want.ConfigurationRev++
	want.TestedRevision = 0
	want.HealthCode = "extension.unknown"
	want.UpdatedAt = got.UpdatedAt
	if !reflect.DeepEqual(want, got) || survivor() != otherBefore || runtime.calls != 0 {
		t.Fatal("deletion changed unrelated state or runtime")
	}
	check(db.QueryRow("SELECT count(*) FROM extension_secrets WHERE instance_id=$1", id).Scan(&retained))
	if retained != 0 {
		t.Fatal("retained secrets survived")
	}
	var testedNull, consumed bool
	check(db.QueryRow("SELECT tested_revision IS NULL FROM extension_instances WHERE instance_id=$1", id).Scan(&testedNull))
	check(db.QueryRow("SELECT consumed_at IS NOT NULL FROM extension_operation_previews WHERE id=$1", p.ID).Scan(&consumed))
	if !testedNull || !consumed {
		t.Fatal("delete reset/consumption missing")
	}
	var count int
	check(db.QueryRow("SELECT count(*) FROM audit_events WHERE resource_id=$1 AND action='extension.secrets.delete'", id).Scan(&count))
	if count != 1 {
		t.Fatal("delete audit mismatch")
	}
	after := targetUISnapshot(t, db)
	replay := request()
	if replay.Code != 200 || !strings.Contains(replay.Body.String(), "extension confirmation rejected") || !reflect.DeepEqual(after, targetUISnapshot(t, db)) {
		t.Fatal("replay changed state")
	}
}
