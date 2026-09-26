package httpui

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http/httptest"
	"net/url"
	"os"
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

func TestExtensionSecretFieldRequirement(t *testing.T) {
	for _, tc := range []struct {
		name     string
		required bool
		status   []extensionsadmin.SecretStatus
		want     bool
	}{
		{"configured-required", true, []extensionsadmin.SecretStatus{{Slot: "webhook.key", Configured: true}}, false},
		{"unconfigured-required", true, []extensionsadmin.SecretStatus{{Slot: "webhook.key"}}, true},
		{"missing-status", true, nil, true},
		{"unrelated-status", true, []extensionsadmin.SecretStatus{{Slot: "other.key", Configured: true}}, true},
		{"optional-missing", false, nil, false},
		{"optional-configured", false, []extensionsadmin.SecretStatus{{Slot: "webhook.key", Configured: true}}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			item := extensionsadmin.Instance{Metadata: extensionsadmin.Metadata{Schema: extensionsadmin.MetadataSchema, Fields: []extensionsadmin.Field{{Name: "webhook.key", Label: "HMAC key", Kind: extensionsadmin.FieldSecret, Required: tc.required}, {Name: "webhook.mode", Label: "Mode", Kind: extensionsadmin.FieldEnum, Required: true, Options: []string{"one", "two"}}}}, SecretSlots: []string{"webhook.key"}, Secrets: tc.status, Configuration: map[string]any{"webhook.key": "must-never-render", "webhook.mode": "one"}}
			fields := extensionFields(item, map[string]any{"webhook.key": "override-must-not-render", "webhook.mode": "two"})
			if len(fields) != 2 || fields[0].Required != tc.want || fields[0].Value != "" || fields[0].Checked || !fields[1].Required || fields[1].Value != "two" {
				t.Errorf("incorrect required/write-only/non-secret projection")
			}
			fields[1].Options[0] = "changed"
			if item.Metadata.Fields[1].Options[0] != "one" {
				t.Fatal("option copy aliases metadata")
			}
		})
	}
	// There is no independent metadata SecretSlot property or alias mapping.
	metadata := extensionsadmin.Metadata{Schema: extensionsadmin.MetadataSchema, Fields: []extensionsadmin.Field{{Name: "webhook.key", Label: "Key", Kind: extensionsadmin.FieldSecret}}}
	if _, err := extensionsadmin.ValidateConfiguration(metadata, nil, []string{"other.key"}); err == nil {
		t.Fatal("mismatched field/slot alias accepted")
	}
}

// Runtime is an explicit failure sentinel: required-secret denial must occur BEFORE Start.
// This fixture proves UI/SQL secret retention, not real process/delivery (credited elsewhere).
type retentionRuntime struct{ starts int }

func (r *retentionRuntime) Start(context.Context, extensionsadmin.Instance, map[string][]byte) error {
	r.starts++
	return errors.New("unexpected runtime start")
}
func (*retentionRuntime) Probe(context.Context, extensionsadmin.Instance) (extensionsadmin.Health, error) {
	return extensionsadmin.Health{}, errors.New("unexpected probe")
}
func (*retentionRuntime) AdmitRouting(context.Context, extensionsadmin.Instance) error {
	return errors.New("unexpected routing")
}
func (*retentionRuntime) RevokeRouting(context.Context, extensionsadmin.Instance) error { return nil }
func (*retentionRuntime) Stop(context.Context, extensionsadmin.Instance) error          { return nil }

func TestExtensionConfiguredSecretRetention(t *testing.T) {
	check := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	random := func() string { b := make([]byte, 32); _, err := rand.Read(b); check(err); return hex.EncodeToString(b) }
	db := testpg.DB(t, store.MigrateSQL)
	var version int
	check(db.QueryRow("SELECT current_setting('server_version_num')::int").Scan(&version))
	if os.Getenv("GOTTH_RETENTION_REQUIRE_PG16") == "1" && (version < 160000 || version >= 170000) {
		t.Fatalf("PG16 required: %d", version)
	}
	t.Logf("PostgreSQL version=%d", version)
	runtime := &retentionRuntime{}
	master := sha256.Sum256([]byte(random()))
	svc, err := extensionsadmin.NewService(db, master[:], runtime)
	check(err)
	now := time.Date(2026, 9, 26, 22, 0, 0, 0, time.UTC)
	svc.Now = func() time.Time { return now }
	csrf, sid := random(), random()
	owner := authn.BoundSession{Session: authn.Session{ID: sid, IdentityRefID: "retention-owner", CreatedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour), CSRFSecretHash: csrfHash(csrf)}, Mailbox: "admin@example.test", Roles: []authz.RoleAssignment{{Role: authz.RoleGlobalAdmin}}}
	id := "b4aa252e-265b-44a1-9a67-90f2ace3d6b9"
	_, err = svc.Install(context.Background(), audit.ActorRef{Type: "local_admin", ID: "fixture"}, extensionsadmin.InstallRequest{InstanceID: id, ExtensionID: "notification.retention", Repository: "https://github.com/gotthboard/gotth-extension-retention", ArtifactPin: "sha256:" + random(), ManifestDigest: random(), GrantDigest: random(), SessionDigest: random(), SecretSlots: []string{"webhook.key"}, Metadata: extensionsadmin.Metadata{Schema: extensionsadmin.MetadataSchema, Fields: []extensionsadmin.Field{{Name: "webhook.endpoint", Label: "Endpoint", Kind: extensionsadmin.FieldString, Required: true}, {Name: "webhook.key", Label: "HMAC key", Kind: extensionsadmin.FieldSecret, Required: true}}}})
	check(err)
	oldKey, newKey, differentKey := random(), random(), random()
	handler := HandlerWithAdminIdentitySessionsAndExtensions(admin.NewStore(), identity.NewService("example.test"), authz.StaticAuthorizer{}, uiSessionStore{bound: owner}, func() time.Time { return now }, svc)
	request := func(method string, values url.Values) *httptest.ResponseRecorder {
		t.Helper()
		req := formReq(method, "/admin/extensions/"+id, values, "")
		withIdentityCookies(req, sid, csrf)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		for _, secret := range []string{oldKey, newKey, differentKey} {
			if strings.Contains(w.Body.String(), secret) {
				t.Fatal("secret exposed in route HTML")
			}
		}
		return w
	}
	current := func() extensionsadmin.Instance {
		t.Helper()
		item, err := svc.Get(context.Background(), id)
		check(err)
		return item
	}
	type encryptedRow struct {
		Nonce, Ciphertext   []byte
		Version             int
		Configured, Rotated time.Time
	}
	encrypted := func() encryptedRow {
		t.Helper()
		var row encryptedRow
		check(db.QueryRow("SELECT nonce,ciphertext,key_version,configured_at,rotated_at FROM extension_secrets WHERE instance_id=$1 AND slot='webhook.key'", id).Scan(&row.Nonce, &row.Ciphertext, &row.Version, &row.Configured, &row.Rotated))
		return row
	}
	clone := func(v url.Values) url.Values {
		out := url.Values{}
		for k, v := range v {
			out[k] = append([]string(nil), v...)
		}
		return out
	}
	required := func(body, action string, want bool) {
		t.Helper()
		form, _, _ := updateForm(t, body, action)
		found := false
		walkUpdateHTML(form, func(n *html.Node) {
			if n.Data != "input" || updateAttr(n, "name") != "field.webhook.key" {
				return
			}
			found = true
			has := false
			for _, a := range n.Attr {
				if a.Key == "required" {
					has = true
				}
				if a.Key == "disabled" {
					t.Error("secret input disabled")
				}
			}
			if has != want || updateAttr(n, "type") != "password" || updateAttr(n, "value") != "" {
				t.Errorf("native secret required=%v want=%v or non-write-only", has, want)
			}
		})
		if !found {
			t.Fatal("missing native secret input")
		}
	}
	capture := func(name, body string) {
		t.Helper()
		if dir := os.Getenv("GOTTH_RETENTION_HTML_DIR"); dir != "" {
			check(os.WriteFile(filepath.Join(dir, name+".html"), []byte(body), 0600))
		}
	}
	preview := func(endpoint, secret string) url.Values {
		t.Helper()
		before := current()
		v := url.Values{"action": {"configure-preview"}, "csrf_token": {csrf}, "field.webhook.endpoint": {endpoint}, "field.webhook.key": {secret}}
		res := request("POST", v)
		if res.Code != 200 || !strings.Contains(res.Body.String(), "extension operation accepted") {
			t.Fatal("preview rejected")
		}
		if !reflect.DeepEqual(before, current()) {
			t.Fatal("preview mutated state")
		}
		_, apply, confirmation := updateForm(t, res.Body.String(), "configure-apply")
		apply.Set("confirmation", confirmation)
		apply.Set("field.webhook.endpoint", endpoint)
		apply.Set("field.webhook.key", secret)
		return apply
	}
	applyOK := func(v url.Values) {
		t.Helper()
		res := request("POST", v)
		if res.Code != 200 || !strings.Contains(res.Body.String(), "extension operation accepted") {
			t.Fatal("apply rejected")
		}
	}
	// Missing required initial secret remains a native constraint; backend allows staging,
	// but neither readiness nor enable can pass without the secret.
	initial := request("GET", nil)
	required(initial.Body.String(), "configure-preview", true)
	applyOK(preview("https://example.test/initial", ""))
	beforeMissing := current()
	for _, action := range []string{"test", "enable"} {
		res := request("POST", url.Values{"action": {action}, "csrf_token": {csrf}})
		if res.Code != 200 || strings.Contains(res.Body.String(), "extension operation accepted") || !reflect.DeepEqual(beforeMissing, current()) || runtime.starts != 0 {
			t.Fatalf("missing secret %s did not fail before runtime", action)
		}
	}
	applyOK(preview("https://example.test/initial", oldKey))
	saved := encrypted()
	if bytes.Contains(saved.Ciphertext, []byte(oldKey)) {
		t.Fatal("plaintext secret stored")
	}
	detail := request("GET", nil)
	capture("configured-detail", detail.Body.String())
	required(detail.Body.String(), "configure-preview", false)
	before := current()
	configOnly := url.Values{"action": {"configure-preview"}, "csrf_token": {csrf}, "field.webhook.endpoint": {"https://example.test/changed"}, "field.webhook.key": {""}}
	response := request("POST", configOnly)
	if response.Code != 200 {
		t.Fatal("config preview status")
	}
	capture("configured-preview", response.Body.String())
	required(response.Body.String(), "configure-apply", false)
	if !reflect.DeepEqual(before, current()) || !reflect.DeepEqual(saved, encrypted()) {
		t.Fatal("config preview mutated registry or secret")
	}
	_, apply, confirmation := updateForm(t, response.Body.String(), "configure-apply")
	apply.Set("confirmation", confirmation)
	apply.Set("field.webhook.endpoint", "https://example.test/changed")
	deny := func(values url.Values, wantCode int) {
		t.Helper()
		before := current()
		row := encrypted()
		res := request("POST", values)
		if res.Code != wantCode || strings.Contains(res.Body.String(), "extension operation accepted") || !reflect.DeepEqual(before, current()) || !reflect.DeepEqual(row, encrypted()) {
			t.Fatal("denied operation changed state")
		}
		if res.Code == 200 {
			required(res.Body.String(), "configure-preview", false)
		}
	}
	missingCSRF := clone(apply)
	missingCSRF.Del("csrf_token")
	deny(missingCSRF, 403)
	wrongCSRF := clone(apply)
	wrongCSRF.Set("csrf_token", "wrong")
	deny(wrongCSRF, 403)
	wrongConfirmation := clone(apply)
	wrongConfirmation.Set("confirmation", "wrong")
	deny(wrongConfirmation, 200)
	wrongConfig := clone(apply)
	wrongConfig.Set("field.webhook.endpoint", "https://example.test/tampered")
	deny(wrongConfig, 200)
	now = now.Add(time.Second)
	applyOK(apply)
	after := current()
	if after.ConfigurationRev != before.ConfigurationRev+1 || after.Configuration["webhook.endpoint"] != "https://example.test/changed" || !reflect.DeepEqual(saved, encrypted()) {
		t.Fatal("config-only apply did not preserve encrypted secret")
	}
	deny(apply, 200)
	t.Log("config-only route apply preserved nonce/ciphertext/key-version/configured-at/rotated-at")
	// Existing configured status cannot waive re-entry of a previewed rotation.
	rotation := preview("https://example.test/rotated", newKey)
	omitted := clone(rotation)
	omitted.Set("field.webhook.key", "")
	deny(omitted, 200)
	changed := clone(rotation)
	changed.Set("field.webhook.key", differentKey)
	deny(changed, 200)
	now = now.Add(time.Second)
	applyOK(rotation)
	rotated := encrypted()
	if bytes.Equal(rotated.Ciphertext, saved.Ciphertext) || bytes.Equal(rotated.Nonce, saved.Nonce) || !rotated.Rotated.After(saved.Rotated) || rotated.Configured != saved.Configured {
		t.Fatal("matching rotation did not rotate exactly the secret row")
	}
	t.Log("rotation missing/different re-entry denied; matching accepted; secret-free HTML")
}
