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

func TestExtensionRollbackUninstallComponent(t *testing.T) {
	view := extensionPageView{CSRF: "csrf-fixture", ActionURL: extensionDetailActionURL("{alias}", "dark"), Item: extensionsadmin.Instance{ExtensionID: "id.<script>", PreviousArtifact: "previous-<script>"}, Preview: extensionsadmin.Preview{Operation: "uninstall", ID: "preview-fixture", Confirmation: "confirm-fixture"}}
	var out strings.Builder
	if err := extensionRollbackUninstallForms(view).Render(context.Background(), &out); err != nil {
		t.Fatal(err)
	}
	body := out.String()
	if strings.Contains(body, "<script>") || !strings.Contains(body, "rollback id.&lt;script&gt; to previous-&lt;script&gt;") || !strings.Contains(body, "Secrets must be deleted separately") {
		t.Fatal("unsafe/missing phrase or scope")
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
	if len(forms) != 3 || forms[0].Parent != forms[1].Parent || forms[1].Parent != forms[2].Parent {
		t.Fatal("forms not siblings")
	}
	for _, action := range []string{"rollback", "uninstall-preview", "uninstall-apply"} {
		form, v, _ := updateForm(t, body, action)
		want := url.Values{"csrf_token": {"csrf-fixture"}, "action": {action}}
		if action != "uninstall-preview" {
			want.Set("confirmation", "")
		}
		if action == "uninstall-apply" {
			want.Set("preview_id", "preview-fixture")
		}
		if !reflect.DeepEqual(v, want) || updateAttr(form, "action") != view.ActionURL {
			t.Fatal("wrong controls/route")
		}
		required := 0
		walkUpdateHTML(form, func(n *html.Node) {
			for _, a := range n.Attr {
				if a.Key == "required" {
					required++
					if updateAttr(n, "name") != "confirmation" || n.Parent.Data != "label" {
						t.Error("missing confirmation label")
					}
				}
			}
		})
		expected := 1
		if action == "uninstall-preview" {
			expected = 0
		}
		if required != expected {
			t.Fatal("Preview blocked by Apply/rollback constraint")
		}
	}
	view.Item.PreviousArtifact = ""
	view.Preview.Operation = "delete_secrets"
	out.Reset()
	if err := extensionRollbackUninstallForms(view).Render(context.Background(), &out); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), `value="rollback"`) || strings.Contains(out.String(), "uninstall-apply") || strings.Contains(out.String(), "preview-fixture") {
		t.Fatal("conditional authority fabricated")
	}
	updateForm(t, out.String(), "uninstall-preview")
}

func TestExtensionRollbackUninstallComponentRoute(t *testing.T) {
	db := testpg.DB(t, store.MigrateSQL)
	check := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatalf("fixture type=%T", err)
		}
	}
	ids := identity.NewService("example.test")
	check(ids.AddTokenWithScopes("ru-component", "api_token", "ru-component-token", "ops:admin"))
	actor := audit.ActorRef{Type: "api_token", ID: "ru-component"}
	runtime := &targetUIRuntime{}
	svc, err := extensionsadmin.NewService(db, []byte(strings.Repeat("k", 32)), runtime)
	check(err)
	const id = "00000000-0000-4000-8000-000000000094"
	const other = "00000000-0000-4000-8000-000000000095"
	for _, x := range []struct{ id, name string }{{id, "chosen"}, {other, "survivor"}} {
		_, err := svc.Install(context.Background(), actor, extensionsadmin.InstallRequest{InstanceID: x.id, ExtensionID: "notification." + x.name, Repository: "https://github.com/gotthboard/gotth-extension-rollback", ArtifactPin: "sha256:" + strings.Repeat("1", 64), ManifestDigest: strings.Repeat("2", 64), GrantDigest: strings.Repeat("3", 64), SessionDigest: strings.Repeat("4", 64), SecretSlots: []string{"retained.key"}, Metadata: extensionsadmin.Metadata{Schema: extensionsadmin.MetadataSchema}})
		check(err)
		input := extensionsadmin.ConfigureInput{Secrets: map[string]string{"retained.key": "PRIVATE-retained-value"}}
		p, err := svc.PreviewConfigure(context.Background(), actor, x.id, input)
		check(err)
		_, err = svc.ApplyConfigure(context.Background(), actor, x.id, p.ID, p.Confirmation, input)
		check(err)
	}
	original, err := svc.Get(context.Background(), id)
	check(err)
	target := extensionsadmin.UpdateInput{ArtifactPin: "sha256:" + strings.Repeat("5", 64), ManifestDigest: strings.Repeat("6", 64), GrantDigest: strings.Repeat("7", 64), SessionDigest: strings.Repeat("8", 64), Metadata: original.Metadata, SecretSlots: original.SecretSlots}
	p, err := svc.PreviewUpdate(context.Background(), actor, id, target)
	check(err)
	current, err := svc.ApplyUpdate(context.Background(), actor, id, p.ID, p.Confirmation)
	check(err)
	survivor := func() string {
		var s string
		check(db.QueryRow("SELECT jsonb_build_array((SELECT to_jsonb(i) FROM extension_instances i WHERE instance_id=$1),(SELECT jsonb_agg(to_jsonb(s) ORDER BY slot) FROM extension_secrets s WHERE instance_id=$1),(SELECT jsonb_agg(to_jsonb(p) ORDER BY id) FROM extension_operation_previews p WHERE instance_id=$1))::text", other).Scan(&s))
		return s
	}
	otherBefore := survivor()
	h := HandlerWithAdminIdentitySessionsAndExtensions(admin.NewStore(), ids, authz.StaticAuthorizer{}, nil, time.Now, svc)
	request := func(method string, v url.Values) *httptest.ResponseRecorder {
		r := formReq(method, extensionDetailActionURL(id, "dark"), v, "Bearer ru-component-token")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	var out strings.Builder
	check(extensionRollbackUninstallForms(extensionPageView{Item: current, ActionURL: extensionDetailActionURL(id, "dark")}).Render(context.Background(), &out))
	_, v, _ := updateForm(t, out.String(), "rollback")
	before := targetUISnapshot(t, db)
	v.Set("confirmation", "wrong")
	denied := request("POST", v)
	if denied.Code != 200 || !strings.Contains(denied.Body.String(), "extension confirmation rejected") || !reflect.DeepEqual(before, targetUISnapshot(t, db)) {
		t.Fatal("rollback denial mutated state")
	}
	v.Set("confirmation", "rollback "+current.ExtensionID+" to "+current.PreviousArtifact)
	done := request("POST", v)
	if done.Code != 200 || !strings.Contains(done.Body.String(), "extension operation accepted") {
		t.Fatal("rollback rejected")
	}
	rolled, err := svc.Get(context.Background(), id)
	check(err)
	want := original
	want.ConfigurationRev = current.ConfigurationRev + 1
	want.PreviousArtifact = current.ArtifactPin
	want.Lifecycle = "stopped"
	want.HealthCode = "extension.unknown"
	want.TestedRevision = 0
	want.UpdatedAt = rolled.UpdatedAt
	if !reflect.DeepEqual(want, rolled) || runtime.calls != 0 || survivor() != otherBefore {
		t.Fatal("rollback restoration mismatch")
	}
	var audits int
	check(db.QueryRow("SELECT count(*) FROM audit_events WHERE resource_id=$1 AND action='extension.rollback'", id).Scan(&audits))
	if audits != 1 {
		t.Fatal("rollback audit mismatch")
	}
	// Existing retained-slot seam, then explicit service cleanup setup, not component action.
	_, err = db.Exec("UPDATE extension_instances SET secret_slots_json='[]' WHERE instance_id=$1", id)
	check(err)
	rolled, err = svc.Get(context.Background(), id)
	check(err)
	p, err = svc.PreviewUninstall(context.Background(), actor, id)
	check(err)
	out.Reset()
	check(extensionRollbackUninstallForms(extensionPageView{Item: rolled, Preview: p, ActionURL: extensionDetailActionURL(id, "dark")}).Render(context.Background(), &out))
	_, v, phrase := updateForm(t, out.String(), "uninstall-apply")
	v.Set("confirmation", phrase)
	before = targetUISnapshot(t, db)
	denied = request("POST", v)
	if denied.Code != 200 || strings.Contains(denied.Body.String(), "extension operation accepted") || !reflect.DeepEqual(before, targetUISnapshot(t, db)) {
		t.Fatal("retained-secret uninstall did not fail unchanged")
	}
	deletion, err := svc.PreviewDeleteSecrets(context.Background(), actor, id)
	check(err)
	_, err = svc.ApplyDeleteSecrets(context.Background(), actor, id, deletion.ID, deletion.Confirmation)
	check(err)
	p, err = svc.PreviewUninstall(context.Background(), actor, id)
	check(err)
	out.Reset()
	check(extensionRollbackUninstallForms(extensionPageView{Item: rolled, Preview: p, ActionURL: extensionDetailActionURL(id, "dark")}).Render(context.Background(), &out))
	_, v, phrase = updateForm(t, out.String(), "uninstall-apply")
	v.Set("confirmation", phrase)
	done = request("POST", v)
	if done.Code != 200 || !strings.Contains(done.Body.String(), ">Extension uninstalled</h1>") || done.Header().Get("Content-Security-Policy") == "" || !strings.Contains(done.Body.String(), `data-theme="dark"`) || strings.Contains(done.Body.String(), "<form") {
		t.Fatal("existing D1 receipt missing/false")
	}
	for _, q := range []struct {
		sql  string
		want int
	}{{"SELECT count(*) FROM extension_instances WHERE instance_id=$1", 0}, {"SELECT count(*) FROM extension_operation_previews WHERE instance_id=$1", 0}, {"SELECT count(*) FROM audit_events WHERE resource_id=$1 AND action='extension.uninstall'", 1}} {
		var count int
		check(db.QueryRow(q.sql, id).Scan(&count))
		if count != q.want {
			t.Fatal("uninstall/cascade/audit mismatch")
		}
	}
	if survivor() != otherBefore || runtime.calls != 0 || request("GET", nil).Code != 404 {
		t.Fatal("survivor/runtime/old detail mismatch")
	}
	after := targetUISnapshot(t, db)
	if request("POST", v).Code != 404 || !reflect.DeepEqual(after, targetUISnapshot(t, db)) {
		t.Fatal("deleted-target replay changed state")
	}
}
