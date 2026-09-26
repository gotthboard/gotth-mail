package httpui

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
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
	"golang.org/x/net/html"
)

// Successful controls for this closed native form: unchecked checkboxes omitted,
// selected (or first) option submitted, empty named text controls included.
// Chromium separately checks this oracle against actual FormData and validity.
func configurationForm(t *testing.T, body string) (url.Values, string) {
	t.Helper()
	form, _, confirmation := updateForm(t, body, "configure-apply")
	values := url.Values{"action": {"configure-apply"}}
	has := func(n *html.Node, key string) bool {
		for _, a := range n.Attr {
			if a.Key == key {
				return true
			}
		}
		return false
	}
	walkUpdateHTML(form, func(n *html.Node) {
		name := updateAttr(n, "name")
		if name == "" || has(n, "disabled") {
			return
		}
		switch n.Data {
		case "input":
			value := updateAttr(n, "value")
			if updateAttr(n, "type") == "checkbox" {
				if !has(n, "checked") {
					return
				}
				if !has(n, "value") {
					value = "on"
				}
			}
			values.Add(name, value)
		case "select":
			var selected *html.Node
			walkUpdateHTML(n, func(option *html.Node) {
				if option.Data == "option" && (selected == nil || has(option, "selected")) {
					selected = option
				}
			})
			if selected == nil {
				t.Fatal("select lacks options")
			}
			value := updateAttr(selected, "value")
			if !has(selected, "value") {
				walkUpdateHTML(selected, func(text *html.Node) {
					if text.Type == html.TextNode {
						value += text.Data
					}
				})
			}
			values.Add(name, value)
		}
	})
	return values, confirmation
}

func TestExtensionConfigurationRoundtrip(t *testing.T) {
	check := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	if os.Getenv("GOTTH_ROUNDTRIP_REQUIRE_PG16") == "1" {
		for _, name := range []string{"initdb", "postgres", "createdb"} {
			_, err := exec.LookPath(name)
			check(err)
		}
	}
	db := testpg.DB(t, store.MigrateSQL)
	var version int
	check(db.QueryRow("SELECT current_setting('server_version_num')::int").Scan(&version))
	if os.Getenv("GOTTH_ROUNDTRIP_REQUIRE_PG16") == "1" && (version < 160000 || version >= 170000) {
		t.Fatal("PG16 required")
	}
	t.Logf("PostgreSQL=%d", version)
	random := func() string { b := make([]byte, 32); _, err := rand.Read(b); check(err); return hex.EncodeToString(b) }
	svc, err := extensionsadmin.NewService(db, []byte(random()[:32]), &retentionRuntime{})
	check(err)
	now := time.Date(2026, 9, 26, 23, 30, 0, 0, time.UTC)
	svc.Now = func() time.Time { return now }
	csrf, sid := random(), random()
	owner := authn.BoundSession{Session: authn.Session{ID: sid, IdentityRefID: "roundtrip-owner", CreatedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour), CSRFSecretHash: csrfHash(csrf)}, Mailbox: "admin@example.test", Roles: []authz.RoleAssignment{{Role: authz.RoleGlobalAdmin}}}
	handler := HandlerWithAdminIdentitySessionsAndExtensions(admin.NewStore(), identity.NewService("example.test"), authz.StaticAuthorizer{}, uiSessionStore{bound: owner}, func() time.Time { return now }, svc)
	metadata := extensionsadmin.Metadata{Schema: extensionsadmin.MetadataSchema, Fields: []extensionsadmin.Field{
		{Name: "config.text", Label: "Text", Kind: extensionsadmin.FieldString, Required: true},
		{Name: "config.number", Label: "Number", Kind: extensionsadmin.FieldInteger, Required: true},
		{Name: "config.flag", Label: "Flag", Kind: extensionsadmin.FieldBoolean, Default: true},
		{Name: "config.mode", Label: "Mode", Kind: extensionsadmin.FieldEnum, Required: true, Options: []string{"first", "second & final"}},
		{Name: "config.optional", Label: "Optional", Kind: extensionsadmin.FieldString},
		{Name: "config.optionalnumber", Label: "Optional number", Kind: extensionsadmin.FieldInteger},
		{Name: "config.optionalmode", Label: "Optional mode", Kind: extensionsadmin.FieldEnum, Options: []string{"one", "two"}},
		{Name: "config.defaulttext", Label: "Default text", Kind: extensionsadmin.FieldString, Required: true, Default: "default"},
		{Name: "config.defaultnumber", Label: "Default number", Kind: extensionsadmin.FieldInteger, Required: true, Default: float64(7)},
		{Name: "config.defaultmode", Label: "Default mode", Kind: extensionsadmin.FieldEnum, Required: true, Default: "two", Options: []string{"one", "two"}},
		{Name: "config.key", Label: "Secret", Kind: extensionsadmin.FieldSecret, Required: true},
	}}
	for index, name := range []string{"initial-true", "edit-false", "edit-true-defaults", "rotation"} {
		t.Run(name, func(t *testing.T) {
			id := fmt.Sprintf("00000000-0000-4000-8000-%012d", index+700)
			key, newKey := random(), random()
			actor := audit.ActorRef{Type: "local_admin", ID: "fixture"}
			_, err := svc.Install(context.Background(), actor, extensionsadmin.InstallRequest{InstanceID: id, ExtensionID: fmt.Sprintf("notification.roundtrip%d", index), Repository: "https://github.com/gotthboard/gotth-extension-roundtrip", ArtifactPin: "sha256:" + random(), ManifestDigest: random(), GrantDigest: random(), SessionDigest: random(), SecretSlots: []string{"config.key"}, Metadata: metadata})
			check(err)
			current := func() extensionsadmin.Instance {
				item, err := svc.Get(context.Background(), id)
				check(err)
				return item
			}
			secretRow := func() string {
				var row string
				check(db.QueryRow("SELECT COALESCE(jsonb_agg(to_jsonb(s))::text,'[]') FROM extension_secrets s WHERE instance_id=$1", id).Scan(&row))
				return row
			}
			if index > 0 {
				// Fixture precondition only: an existing configured instance, not the roundtrip under test.
				seed := extensionsadmin.ConfigureInput{Configuration: map[string]any{"config.text": "old", "config.number": int64(1), "config.flag": index == 1, "config.mode": "first", "config.optional": "old optional", "config.optionalnumber": int64(8), "config.optionalmode": "one"}, Secrets: map[string]string{"config.key": key}}
				p, err := svc.PreviewConfigure(context.Background(), actor, id, seed)
				check(err)
				_, err = svc.ApplyConfigure(context.Background(), actor, p.ID, p.Confirmation, seed)
				check(err)
			}
			request := func(v url.Values) *httptest.ResponseRecorder {
				req := formReq("POST", "/admin/extensions/"+id, v, "")
				withIdentityCookies(req, sid, csrf)
				res := httptest.NewRecorder()
				handler.ServeHTTP(res, req)
				for _, s := range []string{key, newKey} {
					if strings.Contains(res.Body.String(), s) {
						t.Fatal("secret reflected")
					}
				}
				return res
			}
			submitted := url.Values{"action": {"configure-preview"}, "csrf_token": {csrf}, "field.config.text": {"new <value> & text"}, "field.config.number": {"-42"}, "field.config.mode": {"second & final"}}
			want := map[string]any{"config.text": submitted.Get("field.config.text"), "config.number": float64(-42), "config.flag": index != 1, "config.mode": "second & final"}
			if index != 1 {
				submitted.Set("field.config.flag", "on")
			}
			if index == 2 {
				for k, v := range map[string]string{"config.defaulttext": "override", "config.defaultnumber": "19", "config.defaultmode": "one", "config.optional": "present", "config.optionalnumber": "0", "config.optionalmode": "two"} {
					submitted.Set("field."+k, v)
					want[k] = v
				}
				want["config.defaultnumber"] = float64(19)
				want["config.optionalnumber"] = float64(0)
			}
			reentry := ""
			if index == 0 {
				reentry = key
			}
			if index == 3 {
				reentry = newKey
			}
			if reentry != "" {
				submitted.Set("field.config.key", reentry)
			}
			before, row := current(), secretRow()
			preview := request(submitted)
			if preview.Code != 200 || !strings.Contains(preview.Body.String(), "extension operation accepted") {
				t.Fatal("preview rejected")
			}
			if !reflect.DeepEqual(before, current()) || row != secretRow() {
				t.Fatal("preview mutated instance or secret")
			}
			values, confirmation := configurationForm(t, preview.Body.String())
			if dir := os.Getenv("GOTTH_ROUNDTRIP_HTML_DIR"); dir != "" {
				check(os.WriteFile(filepath.Join(dir, name+".html"), preview.Body.Bytes(), 0600))
				expected := url.Values{"action": {"configure-apply"}, "csrf_token": {csrf}, "preview_id": {values.Get("preview_id")}, "confirmation": {confirmation}}
				for _, field := range metadata.Fields {
					if field.Kind == extensionsadmin.FieldSecret {
						continue
					}
					if field.Kind == extensionsadmin.FieldBoolean && !submitted.Has("field."+field.Name) {
						continue
					}
					expected.Set("field."+field.Name, submitted.Get("field."+field.Name))
				}
				encoded, err := json.Marshal(expected)
				check(err)
				check(os.WriteFile(filepath.Join(dir, name+"-expected.json"), encoded, 0600))
			}
			// The ONLY edits after preview: ordinary confirmation and required secret re-entry.
			values.Set("confirmation", confirmation)
			if reentry != "" {
				values.Set("field.config.key", reentry)
			}
			deny := func(v url.Values, code int) {
				t.Helper()
				b, r := current(), secretRow()
				res := request(v)
				if res.Code != code || strings.Contains(res.Body.String(), "extension operation accepted") || !reflect.DeepEqual(b, current()) || r != secretRow() {
					t.Fatal("denial mutated state or returned success")
				}
			}
			clone := func() url.Values {
				v := url.Values{}
				for k, x := range values {
					v[k] = append([]string(nil), x...)
				}
				return v
			}
			tampered := clone()
			tampered.Set("field.config.text", "tampered")
			deny(tampered, 200)
			badCSRF := clone()
			badCSRF.Set("csrf_token", "wrong")
			deny(badCSRF, 403)
			missingCSRF := clone()
			missingCSRF.Del("csrf_token")
			deny(missingCSRF, 403)
			if reentry != "" {
				missing := clone()
				missing.Set("field.config.key", "")
				deny(missing, 200)
				different := clone()
				different.Set("field.config.key", random())
				deny(different, 200)
			}
			now = now.Add(time.Second)
			applied := request(values)
			if applied.Code != 200 || !strings.Contains(applied.Body.String(), "extension operation accepted") {
				t.Error("ordinary rendered Apply rejected (nonsecret controls were NOT refilled)")
			}
			after := current()
			if after.ConfigurationRev != before.ConfigurationRev+1 || !reflect.DeepEqual(after.Configuration, want) {
				t.Errorf("persisted configuration mismatch: got=%v want=%v", after.Configuration, want)
			}
			if reentry == "" && row != secretRow() {
				t.Error("config-only changed encrypted secret row")
			}
			if reentry != "" && row == secretRow() {
				t.Error("matching secret re-entry not applied")
			}
			deny(values, 200)
			invalid := url.Values{"action": {"configure-preview"}, "csrf_token": {csrf}, "field.config.number": {"not-an-integer"}}
			res := request(invalid)
			if !strings.Contains(res.Body.String(), "invalid integer extension field") || strings.Contains(res.Body.String(), "extension operation accepted") {
				t.Error("validation error quieted")
			}
		})
	}
}
