package httpui

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
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
	"golang.org/x/net/html"
)

// Parse actual routed HTML using the HTML5 tree builder (including form
// ownership), rather than blessing a substring or bypassing native controls.
func updateForm(t *testing.T, body, action string) (*html.Node, url.Values, string) {
	t.Helper()
	root, err := html.Parse(strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	var button *html.Node
	walkUpdateHTML(root, func(n *html.Node) {
		if n.Data == "button" && updateAttr(n, "name") == "action" && updateAttr(n, "value") == action {
			if button != nil {
				t.Fatalf("duplicate %s", action)
			}
			button = n
		}
	})
	if button == nil {
		t.Fatalf("missing %s form", action)
	}
	form := button.Parent
	for form != nil && form.Data != "form" {
		form = form.Parent
	}
	if form == nil {
		t.Fatal("submit button has no native form owner")
	}
	if updateAttr(form, "method") != "post" {
		t.Fatal("confirmation is not ordinary POST")
	}
	for _, n := range []*html.Node{form, button} {
		for _, a := range n.Attr {
			if a.Key == "novalidate" || a.Key == "formnovalidate" || a.Key == "form" || a.Key == "onclick" {
				t.Fatalf("validation/form ownership bypass: %s", a.Key)
			}
		}
	}
	values := url.Values{"action": {action}}
	confirmation := ""
	walkUpdateHTML(form, func(n *html.Node) {
		if n.Data == "input" {
			values.Set(updateAttr(n, "name"), updateAttr(n, "value"))
		}
		if n.Type == html.TextNode && strings.HasPrefix(n.Data, "confirm-") {
			confirmation = n.Data
		}
	})
	return form, values, confirmation
}
func walkUpdateHTML(n *html.Node, visit func(*html.Node)) {
	visit(n)
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		walkUpdateHTML(c, visit)
	}
}
func updateAttr(n *html.Node, key string) string {
	for _, a := range n.Attr {
		if a.Key == key {
			return a.Val
		}
	}
	return ""
}

func TestExtensionUpdateConfirmationHTML(t *testing.T) {
	db := testpg.DB(t, store.MigrateSQL)
	var version int
	if err := db.QueryRow("SELECT current_setting('server_version_num')::int").Scan(&version); err != nil {
		t.Fatal(err)
	}
	if os.Getenv("GOTTH_UPDATE_REQUIRE_PG16") == "1" && (version < 160000 || version >= 170000) {
		t.Fatalf("PostgreSQL16 required, got %d", version)
	}
	t.Logf("PostgreSQL server_version_num=%d", version)
	svc, err := extensionsadmin.NewService(db, []byte(strings.Repeat("k", 32)), nil)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 9, 26, 22, 0, 0, 0, time.UTC)
	svc.Now = func() time.Time { return now }
	const csrf = "update-csrf"
	const sid = "update-session"
	owner := authn.BoundSession{Session: authn.Session{ID: sid, IdentityRefID: "update-owner", CreatedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour), CSRFSecretHash: csrfHash(csrf)}, Mailbox: "admin@example.test", Roles: []authz.RoleAssignment{{Role: authz.RoleGlobalAdmin}}}
	target := url.Values{"action": {"update-preview"}, "csrf_token": {csrf}, "artifact_pin": {"sha256:" + strings.Repeat("5", 64)}, "manifest_sha256": {strings.Repeat("6", 64)}, "grant_sha256": {strings.Repeat("7", 64)}, "session_sha256": {strings.Repeat("8", 64)}, "capabilities": {"notification.send"}, "interfaces": {"notification.v1"}, "secret_slots": {}}
	sequence := 0
	for _, name := range []string{"native-success", "tampered-target", "bad-confirmation", "missing-confirmation", "wrong-csrf", "missing-csrf", "no-session", "restricted-role", "other-actor", "stale", "expired", "enabled", "routed", "missing-preview", "invalid-target"} {
		t.Run(name, func(t *testing.T) {
			sequence++
			id := fmt.Sprintf("00000000-0000-4000-8000-%012d", sequence+200)
			original, err := svc.Install(context.Background(), audit.ActorRef{Type: "local_admin", ID: "fixture"}, extensionsadmin.InstallRequest{InstanceID: id, ExtensionID: fmt.Sprintf("notification.update%d", sequence), Repository: "https://github.com/gotthboard/gotth-extension-update", ArtifactPin: "sha256:" + strings.Repeat("1", 64), ManifestDigest: strings.Repeat("2", 64), GrantDigest: strings.Repeat("3", 64), SessionDigest: strings.Repeat("4", 64), Metadata: extensionsadmin.Metadata{Schema: extensionsadmin.MetadataSchema}})
			if err != nil {
				t.Fatal(err)
			}
			request := func(method string, form url.Values, actor authn.BoundSession, cookies bool) *httptest.ResponseRecorder {
				handler := HandlerWithAdminIdentitySessionsAndExtensions(admin.NewStore(), identity.NewService("example.test"), authz.StaticAuthorizer{}, uiSessionStore{bound: actor}, func() time.Time { return now }, svc)
				req := formReq(method, "/admin/extensions/"+id, form, "")
				if cookies {
					withIdentityCookies(req, sid, csrf)
				}
				res := httptest.NewRecorder()
				handler.ServeHTTP(res, req)
				return res
			}
			clone := func(v url.Values) url.Values {
				out := url.Values{}
				for k, values := range v {
					out[k] = append([]string(nil), values...)
				}
				return out
			}
			previewInput := clone(target)
			if name == "invalid-target" {
				previewInput.Set("artifact_pin", "<script>invalid</script>")
			}
			preview := request(http.MethodPost, previewInput, owner, true)
			if preview.Code != 200 {
				t.Fatalf("preview status=%d", preview.Code)
			}
			unchanged := func() {
				t.Helper()
				got, err := svc.Get(context.Background(), id)
				if err != nil || got.ArtifactPin != original.ArtifactPin || got.ManifestDigest != original.ManifestDigest || got.GrantDigest != original.GrantDigest || got.SessionDigest != original.SessionDigest {
					t.Fatalf("denied/preview mutated target: %#v %v", got, err)
				}
			}
			unchanged()
			if name == "invalid-target" {
				if strings.Contains(preview.Body.String(), `value="update-apply"`) || strings.Contains(preview.Body.String(), "<script>invalid") {
					t.Fatal("invalid target rendered apply or executable input")
				}
				return
			}
			form, apply, confirmation := updateForm(t, preview.Body.String(), "update-apply")
			if confirmation == "" || apply.Get("preview_id") == "" || apply.Get("csrf_token") != csrf {
				t.Fatal("missing bound confirmation controls")
			}
			// Native controls must be satisfiable by typing ONLY confirmation. Preview
			// target inputs must belong to their own independent form, not be disabled.
			if name == "native-success" {
				if path := os.Getenv("GOTTH_UPDATE_HTML_PROOF"); path != "" {
					if err := os.WriteFile(path, preview.Body.Bytes(), 0600); err != nil {
						t.Fatal(err)
					}
				}
				required := 0
				walkUpdateHTML(form, func(n *html.Node) {
					if n.Data == "input" {
						for _, a := range n.Attr {
							if a.Key == "required" {
								required++
								if updateAttr(n, "name") != "confirmation" {
									t.Errorf("native Apply blocked by unrelated required empty %s", updateAttr(n, "name"))
								}
							}
						}
					}
				})
				if required != 1 {
					t.Errorf("confirmation form has %d required inputs, want1", required)
				}
				for _, key := range []string{"artifact_pin", "manifest_sha256", "grant_sha256", "session_sha256", "capabilities", "interfaces", "secret_slots"} {
					if _, ok := apply[key]; ok {
						t.Errorf("confirmation form resubmits target field %s", key)
					}
				}
				updateForm(t, preview.Body.String(), "update-preview")
				walkUpdateHTML(form, func(n *html.Node) {
					if n.Data == "button" && updateAttr(n, "value") == "update-preview" {
						t.Error("preview and apply share a form")
					}
				})
				for _, value := range []string{target.Get("artifact_pin"), target.Get("manifest_sha256"), target.Get("grant_sha256"), target.Get("session_sha256")} {
					if !strings.Contains(preview.Body.String(), value) {
						t.Errorf("exact preview target absent: %s", value)
					}
				}
				get := request(http.MethodGet, nil, owner, true)
				if strings.Contains(get.Body.String(), `value="update-apply"`) {
					t.Error("GET fabricated confirmation")
				}
				unchanged()
			}
			apply.Set("confirmation", confirmation)
			actor := owner
			cookies := true
			switch name {
			case "bad-confirmation":
				apply.Set("confirmation", "wrong")
			case "missing-confirmation":
				apply.Del("confirmation")
			case "wrong-csrf":
				apply.Set("csrf_token", "wrong")
			case "missing-csrf":
				apply.Del("csrf_token")
			case "no-session":
				cookies = false
			case "restricted-role":
				actor.Roles = nil
			case "other-actor":
				actor.Session.IdentityRefID = "other-admin"
				actor.Mailbox = "other@example.test"
			case "stale":
				_, err = db.Exec("UPDATE extension_instances SET configuration_revision=configuration_revision+1 WHERE instance_id=$1", id)
			case "expired":
				now = now.Add(11 * time.Minute)
				defer func() { now = now.Add(-11 * time.Minute) }()
			case "enabled":
				_, err = db.Exec("UPDATE extension_instances SET enabled=true WHERE instance_id=$1", id)
			case "routed":
				_, err = db.Exec("UPDATE extension_instances SET enabled=true,routed=true WHERE instance_id=$1", id)
			case "missing-preview":
				apply.Set("preview_id", "missing")
			}
			if err != nil {
				t.Fatal(err)
			}
			if name == "tampered-target" {
				// Forged target values are not update authority: stored preview wins.
				apply.Set("artifact_pin", "sha256:"+strings.Repeat("9", 64))
				apply.Set("manifest_sha256", strings.Repeat("9", 64))
			}
			result := request(http.MethodPost, apply, actor, cookies)
			if name != "native-success" && name != "tampered-target" {
				if strings.Contains(result.Body.String(), "extension operation accepted") {
					t.Fatalf("%s accepted", name)
				}
				unchanged()
				var consumed bool
				if err := db.QueryRow("SELECT consumed_at IS NOT NULL FROM extension_operation_previews WHERE id=$1", updatePreviewID(t, preview.Body.String())).Scan(&consumed); err != nil || consumed {
					t.Fatalf("denial consumed preview: %t %v", consumed, err)
				}
				return
			}
			got, err := svc.Get(context.Background(), id)
			if err != nil || got.ArtifactPin != target.Get("artifact_pin") || got.ManifestDigest != target.Get("manifest_sha256") || got.GrantDigest != target.Get("grant_sha256") || got.SessionDigest != target.Get("session_sha256") || got.ConfigurationRev != original.ConfigurationRev+1 || got.PreviousArtifact != original.ArtifactPin || got.Enabled || got.Routed || !strings.Contains(result.Body.String(), "extension operation accepted") {
				t.Fatalf("bound update not applied: %#v %v", got, err)
			}
			replay := request(http.MethodPost, apply, owner, true)
			if strings.Contains(replay.Body.String(), "extension operation accepted") {
				t.Fatal("consumed preview replay accepted")
			}
			again, err := svc.Get(context.Background(), id)
			if err != nil || again.ConfigurationRev != got.ConfigurationRev {
				t.Fatal("replay mutated revision", err)
			}
		})
	}
}
func updatePreviewID(t *testing.T, body string) string {
	_, values, _ := updateForm(t, body, "update-apply")
	return values.Get("preview_id")
}
