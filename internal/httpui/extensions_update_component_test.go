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

func TestExtensionUpdateComponent(t *testing.T) {
	view := extensionPageView{ActionURL: extensionDetailActionURL("{alias}", "dark"), CSRF: "csrf-fixture", Item: extensionsadmin.Instance{ArtifactPin: "current-pin", PreviousArtifact: "previous-pin", AvailableUpdate: "available-pin", Capabilities: []string{"a.b", "c.d"}, Interfaces: []string{"e.f"}, SecretSlots: []string{"g.h"}}, UpdateTarget: extensionsadmin.UpdateInput{ArtifactPin: "target-<script>", ManifestDigest: "manifest-target", GrantDigest: "grant-target", SessionDigest: "session-target"}, Preview: extensionsadmin.Preview{ID: "preview-fixture", Operation: "update", Confirmation: "confirm-fixture", PrivilegeDiff: []string{"privilege-<script>"}, ConfigurationDiff: []string{"config-diff"}, SecretSlotDiff: []string{"slot-diff"}}}
	var out strings.Builder
	if err := extensionUpdateForms(view).Render(context.Background(), &out); err != nil {
		t.Fatal(err)
	}
	body := out.String()
	root, err := html.Parse(strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	var forms []*html.Node
	walkUpdateHTML(root, func(n *html.Node) {
		if n.Data == "form" {
			forms = append(forms, n)
		}
		if n.Data == "script" {
			t.Error("injected script")
		}
	})
	if len(forms) != 2 || forms[0].Parent != forms[1].Parent {
		t.Fatal("not sibling forms")
	}
	preview, values, _ := updateForm(t, body, "update-preview")
	apply, accepted, confirmation := updateForm(t, body, "update-apply")
	want := url.Values{"action": {"update-preview"}, "csrf_token": {"csrf-fixture"}, "artifact_pin": {""}, "manifest_sha256": {""}, "grant_sha256": {""}, "session_sha256": {""}, "capabilities": {"a.b,c.d"}, "interfaces": {"e.f"}, "secret_slots": {"g.h"}}
	if !reflect.DeepEqual(values, want) {
		t.Fatal("seven preview control defaults/names changed")
	}
	if !reflect.DeepEqual(accepted, url.Values{"action": {"update-apply"}, "csrf_token": {"csrf-fixture"}, "preview_id": {"preview-fixture"}, "confirmation": {""}}) || confirmation != "confirm-fixture" {
		t.Fatal("Apply resubmits target or lacks binding")
	}
	for _, form := range []*html.Node{preview, apply} {
		if updateAttr(form, "action") != view.ActionURL {
			t.Error("action spelling changed")
		}
	}
	walkUpdateHTML(preview, func(n *html.Node) {
		if n.Data != "input" || updateAttr(n, "type") == "hidden" {
			return
		}
		if n.Parent.Data != "label" {
			t.Error("target lacks visible label")
		}
		hasText := false
		for c := n.Parent.FirstChild; c != nil; c = c.NextSibling {
			if c.Type == html.TextNode && strings.TrimSpace(c.Data) != "" {
				hasText = true
			}
		}
		if !hasText {
			t.Error("empty target label")
		}
		required := false
		for _, a := range n.Attr {
			if a.Key == "required" {
				required = true
			}
		}
		key := updateAttr(n, "name")
		wantRequired := key == "artifact_pin" || key == "manifest_sha256" || key == "grant_sha256" || key == "session_sha256"
		if required != wantRequired {
			t.Error("required contract changed")
		}
	})
	for _, v := range []string{"current-pin", "previous-pin", "available-pin", "target-&lt;script&gt;", "manifest-target", "grant-target", "session-target", "privilege-&lt;script&gt;", "config-diff", "slot-diff"} {
		if !strings.Contains(body, v) {
			t.Error("accepted identity/diff missing or unescaped")
		}
	}
	view.Preview.Operation = "configure"
	out.Reset()
	if err := extensionUpdateForms(view).Render(context.Background(), &out); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), "update-apply") || strings.Contains(out.String(), "preview-fixture") {
		t.Fatal("wrong preview exposed Apply")
	}
}

func TestExtensionUpdateComponentStoredTarget(t *testing.T) {
	db := testpg.DB(t, store.MigrateSQL)
	check := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatalf("fixture type=%T", err)
		}
	}
	ids := identity.NewService("example.test")
	check(ids.AddTokenWithScopes("update-component", "api_token", "update-component-token", "ops:admin"))
	runtime := &targetUIRuntime{}
	svc, err := extensionsadmin.NewService(db, []byte(strings.Repeat("k", 32)), runtime)
	check(err)
	const id = "00000000-0000-4000-8000-000000000091"
	item, err := svc.Install(context.Background(), audit.ActorRef{Type: "local_admin", ID: "fixture"}, extensionsadmin.InstallRequest{InstanceID: id, ExtensionID: "notification.component", Repository: "https://github.com/gotthboard/gotth-extension-update", ArtifactPin: "sha256:" + strings.Repeat("1", 64), ManifestDigest: strings.Repeat("2", 64), GrantDigest: strings.Repeat("3", 64), SessionDigest: strings.Repeat("4", 64), Metadata: extensionsadmin.Metadata{Schema: extensionsadmin.MetadataSchema}})
	check(err)
	h := HandlerWithAdminIdentitySessionsAndExtensions(admin.NewStore(), ids, authz.StaticAuthorizer{}, nil, time.Now, svc)
	request := func(v url.Values) *httptest.ResponseRecorder {
		r := formReq("POST", extensionDetailActionURL(id, "light"), v, "Bearer update-component-token")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	target := extensionsadmin.UpdateInput{ArtifactPin: "sha256:" + strings.Repeat("5", 64), ManifestDigest: strings.Repeat("6", 64), GrantDigest: strings.Repeat("7", 64), SessionDigest: strings.Repeat("8", 64), Capabilities: []string{"notification.send"}, Interfaces: []string{"notification.v1"}, Metadata: item.Metadata}
	p, err := svc.PreviewUpdate(context.Background(), audit.ActorRef{Type: "api_token", ID: "update-component"}, id, target)
	check(err)
	var out strings.Builder
	check(extensionUpdateForms(extensionPageView{Item: item, UpdateTarget: target, Preview: p, ActionURL: extensionDetailActionURL(id, "light")}).Render(context.Background(), &out))
	_, v, confirmation := updateForm(t, out.String(), "update-apply")
	before := targetUISnapshot(t, db)
	v.Set("confirmation", "wrong")
	denied := request(v)
	if denied.Code != 200 || !strings.Contains(denied.Body.String(), "extension confirmation rejected") || !reflect.DeepEqual(before, targetUISnapshot(t, db)) {
		t.Fatal("denial changed durable state")
	}
	v.Set("confirmation", confirmation)
	for _, k := range []string{"artifact_pin", "manifest_sha256", "grant_sha256", "session_sha256", "capabilities", "interfaces", "secret_slots"} {
		v.Set(k, "forged-target")
	}
	applied := request(v)
	if applied.Code != 200 || !strings.Contains(applied.Body.String(), "extension operation accepted") {
		t.Fatal("stored target apply rejected")
	}
	got, err := svc.Get(context.Background(), id)
	check(err)
	if got.ArtifactPin != target.ArtifactPin || got.ManifestDigest != target.ManifestDigest || got.GrantDigest != target.GrantDigest || got.SessionDigest != target.SessionDigest || !reflect.DeepEqual(got.Capabilities, target.Capabilities) || !reflect.DeepEqual(got.Interfaces, target.Interfaces) || len(got.SecretSlots) != 0 || got.PreviousArtifact != item.ArtifactPin || got.ConfigurationRev != item.ConfigurationRev+1 || got.Enabled || got.Routed || runtime.calls != 0 {
		t.Fatal("forged input replaced stored target or wrong effects")
	}
	var consumed bool
	check(db.QueryRow("SELECT consumed_at IS NOT NULL FROM extension_operation_previews WHERE id=$1", p.ID).Scan(&consumed))
	if !consumed {
		t.Fatal("preview not consumed")
	}
	var count int
	check(db.QueryRow("SELECT count(*) FROM audit_events WHERE resource_id=$1 AND action='extension.update'", id).Scan(&count))
	if count != 1 {
		t.Fatal("update audit mismatch")
	}
	after := targetUISnapshot(t, db)
	replay := request(v)
	if replay.Code != 200 || !strings.Contains(replay.Body.String(), "extension confirmation rejected") || !reflect.DeepEqual(after, targetUISnapshot(t, db)) {
		t.Fatal("replay changed state")
	}
}
