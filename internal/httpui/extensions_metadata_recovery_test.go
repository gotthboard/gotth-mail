package httpui

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
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
	"golang.org/x/net/html"
)

const metadataRecoveryID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
const metadataRecoveryOther = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
const metadataRecoveryAlias = "{aaaa-aaaa-aaaa-4aaa-8aaa-aaaa-aaaa-aaaa}"
const metadataRecoveryCanary = "PRIVATE-metadata-recovery-canary"
const metadataRecoveryCSRF = "nonstandard-length-recovery-csrf"

// Only doubles; no extension executable, network or real runtime activation.
type metadataRecoveryRuntime struct {
	recoveryRuntime
	stopErr error
}

func (r *metadataRecoveryRuntime) Stop(context.Context, extensionsadmin.Instance) error {
	r.calls = append(r.calls, "stop")
	return r.stopErr
}

type metadataRecoveryFixture struct {
	db      *sql.DB
	svc     *extensionsadmin.Service
	runtime *metadataRecoveryRuntime
	handler http.Handler
	now     time.Time
	bound   authn.BoundSession
	ids     *identity.Service
}

func metadataRecoveryCheck(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("fixture/query/readback failed: %T", err)
	}
}
func newMetadataRecoveryFixture(t *testing.T) *metadataRecoveryFixture {
	t.Helper()
	f := &metadataRecoveryFixture{db: testpg.DB(t, store.MigrateSQL), runtime: &metadataRecoveryRuntime{}, now: time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC), ids: identity.NewService("example.test")}
	var err error
	f.svc, err = extensionsadmin.NewService(f.db, []byte(strings.Repeat("k", 32)), f.runtime)
	metadataRecoveryCheck(t, err)
	f.svc.Now = func() time.Time { return f.now }
	for i, id := range []string{metadataRecoveryID, metadataRecoveryOther} {
		_, err = f.svc.Install(context.Background(), audit.ActorRef{Type: "local_admin", ID: "fixture"}, extensionsadmin.InstallRequest{InstanceID: id, ExtensionID: fmt.Sprintf("notification.metarecovery%d", i), Repository: "https://github.com/gotthboard/gotth-extension-recovery", ArtifactPin: "sha256:" + strings.Repeat("1", 64), ManifestDigest: strings.Repeat("2", 64), GrantDigest: strings.Repeat("3", 64), SessionDigest: strings.Repeat("4", 64), SecretSlots: []string{"retained.key"}, Metadata: extensionsadmin.Metadata{Schema: extensionsadmin.MetadataSchema, Fields: []extensionsadmin.Field{{Name: "config.text", Label: "Text", Kind: extensionsadmin.FieldString}}}})
		metadataRecoveryCheck(t, err)
	}
	f.bound = authn.BoundSession{Session: authn.Session{ID: "metadata-recovery-session", IdentityRefID: "admin", CreatedAt: f.now.Add(-time.Minute), ExpiresAt: f.now.Add(time.Hour), CSRFSecretHash: csrfHash(metadataRecoveryCSRF)}, Mailbox: "admin@example.test", Roles: []authz.RoleAssignment{{Role: authz.RoleGlobalAdmin}}}
	f.handler = f.withBound(f.bound)
	return f
}
func (f *metadataRecoveryFixture) withBound(b authn.BoundSession) http.Handler {
	return HandlerWithAdminIdentitySessionsAndExtensions(admin.NewStore(), f.ids, authz.StaticAuthorizer{}, uiSessionStore{bound: b}, func() time.Time { return f.now }, f.svc)
}
func (f *metadataRecoveryFixture) request(method, id string, v url.Values) *httptest.ResponseRecorder {
	if v == nil {
		v = url.Values{}
	}
	v = metadataRecoveryValues(v)
	v.Set("csrf_token", metadataRecoveryCSRF)
	r := formReq(method, extensionDetailActionURL(id, "dark"), v, "")
	withIdentityCookies(r, "metadata-recovery-session", metadataRecoveryCSRF)
	w := httptest.NewRecorder()
	f.handler.ServeHTTP(w, r)
	return w
}

// Corrupt persisted schema through SQL is SETUP, never admitted product write credit.
func (f *metadataRecoveryFixture) corrupt(t *testing.T, raw string) {
	t.Helper()
	_, err := f.db.Exec("UPDATE extension_instances SET metadata_json=$1::jsonb WHERE instance_id=$2", raw, metadataRecoveryID)
	metadataRecoveryCheck(t, err)
	if _, err = f.svc.Get(context.Background(), metadataRecoveryID); err != nil {
		t.Fatalf("SETUP expected decodable metadata: %T", err)
	}
}
func metadataRecoveryValues(v url.Values) url.Values {
	out := url.Values{}
	for k, values := range v {
		out[k] = append([]string(nil), values...)
	}
	return out
}
func metadataRecoveryRaw(kind, def string) string {
	tail := ""
	if def != "" {
		tail = `,"default":` + def
	}
	return fmt.Sprintf(`{"schema":%q,"fields":[{"name":"config.text","label":%q,"kind":%q%s}]}`, extensionsadmin.MetadataSchema, metadataRecoveryCanary, kind, tail)
}
func metadataRecoveryDocument(t *testing.T, w *httptest.ResponseRecorder) {
	t.Helper()
	body := w.Body.String()
	if w.Code != 200 || !strings.HasPrefix(strings.ToLower(body), "<!doctype html>") || !strings.Contains(body, "Extension recovery — invalid configuration metadata") {
		t.Errorf("RECOVERY missing explicit complete document: HTTP %d", w.Code)
	}
	if w.Header().Get("Cache-Control") != "private, no-store" || w.Header().Get("Content-Security-Policy") == "" {
		t.Error("RECOVERY privacy headers missing")
	}
	if !strings.Contains(body, `data-theme="dark"`) {
		t.Error("RECOVERY theme missing")
	}
	for _, s := range []string{metadataRecoveryCanary, `name="field.`, `value="test"`, `value="enable"`, `value="configure-preview"`, `value="update-preview"`} {
		if strings.Contains(body, s) {
			t.Error("RECOVERY unsafe field/action/canary projection", s)
		}
	}
}
func metadataRecoveryUnchanged(t *testing.T, f *metadataRecoveryFixture, before map[string]string, calls int) {
	t.Helper()
	after := targetUISnapshot(t, f.db)
	for table, want := range before {
		if after[table] != want {
			t.Error("DENIAL changed table", table)
		}
	}
	if len(f.runtime.calls) != calls {
		t.Error("DENIAL entered runtime")
	}
}

func TestExtensionMetadataRecoveryReadMatrix(t *testing.T) {
	f := newMetadataRecoveryFixture(t)
	base := metadataRecoveryRaw("string", "")
	var m extensionsadmin.Metadata
	metadataRecoveryCheck(t, json.Unmarshal([]byte(base), &m))
	m.Fields = nil
	for i := 0; i < 65; i++ {
		m.Fields = append(m.Fields, extensionsadmin.Field{Name: fmt.Sprintf("field.n%d", i), Label: metadataRecoveryCanary, Kind: extensionsadmin.FieldString})
	}
	oversized, err := json.Marshal(m)
	metadataRecoveryCheck(t, err)
	cases := []struct{ name, raw string }{
		{"schema", strings.Replace(base, extensionsadmin.MetadataSchema, "invalid", 1)},
		{"kind", metadataRecoveryRaw("unknown", "")},
		{"label", strings.Replace(base, metadataRecoveryCanary, metadataRecoveryCanary+"<script>", 1)},
		{"duplicatefields", strings.Replace(base, "]}", ","+strings.SplitN(strings.SplitN(base, "[", 2)[1], "]}", 2)[0]+"]}", 1)},
		{"default", metadataRecoveryRaw("integer", "1.5")},
		{"oversize-fields", string(oversized)},
		{"null-metadata", "null"},
		{"float-upper", metadataRecoveryRaw("integer", "9223372036854775808.0")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f.corrupt(t, tc.raw)
			before := targetUISnapshot(t, f.db)
			calls := len(f.runtime.calls)
			w := f.request("GET", metadataRecoveryAlias, nil)
			metadataRecoveryDocument(t, w)
			metadataRecoveryUnchanged(t, f, before, calls)
		})
	}
	for _, def := range []string{"1.0", "1e0", "null", "9007199254740993", "9223372036854775807", "-9223372036854775808"} {
		t.Run("legacy-"+def, func(t *testing.T) {
			f.corrupt(t, metadataRecoveryRaw("integer", def))
			before := targetUISnapshot(t, f.db)
			w := f.request("GET", metadataRecoveryAlias, nil)
			if w.Code != 200 || !strings.Contains(w.Body.String(), `id="configuration"`) || strings.Contains(w.Body.String(), "invalid configuration metadata") {
				t.Error("COMPAT legacy valid metadata lost normal detail")
			}
			metadataRecoveryUnchanged(t, f, before, 0)
		})
	}
}
func TestExtensionMetadataRecoveryWithheld(t *testing.T) {
	// Independent fixtures prevent an actual bug's mutation from contaminating another case.
	for _, action := range []string{"test", "enable", "configure-preview", "configure-apply", "update-preview", "unknown"} {
		t.Run(action, func(t *testing.T) {
			f := newMetadataRecoveryFixture(t)
			f.corrupt(t, strings.Replace(metadataRecoveryRaw("string", ""), extensionsadmin.MetadataSchema, "invalid", 1))
			before := targetUISnapshot(t, f.db)
			w := f.request("POST", metadataRecoveryID, url.Values{"action": {action}, "field.config.text": {"unreviewed"}})
			metadataRecoveryDocument(t, w)
			metadataRecoveryUnchanged(t, f, before, 0)
			if !strings.Contains(w.Body.String(), "Operation unavailable while configuration metadata is invalid") || !strings.Contains(w.Body.String(), `role="alert"`) || strings.Contains(w.Body.String(), "extension operation accepted") {
				t.Error("DENIAL fixed unavailable alert absent")
			}
		})
	}
}
func TestExtensionMetadataRecoveryBoundary(t *testing.T) {
	f := newMetadataRecoveryFixture(t)
	f.corrupt(t, metadataRecoveryRaw("unknown", ""))
	for _, tc := range []struct {
		name   string
		status int
	}{{"unauth", 401}, {"role", 403}, {"csrf", 403}, {"missing", 404}, {"target", 403}, {"decode", 400}} {
		t.Run(tc.name, func(t *testing.T) {
			h := f.handler
			id := metadataRecoveryID
			v := url.Values{"action": {"disable"}, "csrf_token": {metadataRecoveryCSRF}}
			if tc.name == "role" {
				b := f.bound
				b.Roles = nil
				h = f.withBound(b)
			}
			if tc.name == "csrf" {
				v.Set("csrf_token", "wrong")
			}
			if tc.name == "missing" {
				id = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
			}
			if tc.name == "decode" {
				_, err := f.db.Exec(`UPDATE extension_instances SET metadata_json='{"fields":"PRIVATE"}'::jsonb WHERE instance_id=$1`, metadataRecoveryID)
				metadataRecoveryCheck(t, err)
			}
			r := formReq("POST", extensionDetailActionURL(id, "dark"), v, "")
			if tc.name != "unauth" {
				withIdentityCookies(r, "metadata-recovery-session", metadataRecoveryCSRF)
			}
			if tc.name == "target" {
				metadataRecoveryCheck(t, f.ids.AddTokenWithScopes("narrow", "api_token", "metadata-narrow-token", "ops:admin:"+metadataRecoveryOther))
				r.Header.Set("Authorization", "Bearer metadata-narrow-token")
			}
			before := targetUISnapshot(t, f.db)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != tc.status || strings.Contains(w.Body.String(), "PRIVATE") {
				t.Errorf("BOUNDARY status=%d want=%d", w.Code, tc.status)
			}
			metadataRecoveryUnchanged(t, f, before, 0)
		})
	}
}
func TestExtensionMetadataRecoveryDisable(t *testing.T) {
	for _, state := range []string{"enabled", "partial-error"} {
		t.Run(state, func(t *testing.T) {
			f := newMetadataRecoveryFixture(t)
			f.corrupt(t, metadataRecoveryRaw("unknown", ""))
			_, err := f.db.Exec("UPDATE extension_instances SET enabled=true,routed=true WHERE instance_id=$1", metadataRecoveryID)
			metadataRecoveryCheck(t, err)
			if state == "partial-error" {
				f.runtime.stopErr = errors.New(metadataRecoveryCanary)
			}
			before := targetUISnapshot(t, f.db)
			w := f.request("POST", metadataRecoveryID, url.Values{"action": {"disable"}})
			metadataRecoveryDocument(t, w)
			if !reflect.DeepEqual(f.runtime.calls, []string{"revoke", "stop"}) {
				t.Error("DISABLE runtime sequence")
			}
			after := targetUISnapshot(t, f.db)
			if state == "partial-error" {
				if !reflect.DeepEqual(before, after) {
					t.Error("DISABLE partial failure SQL changed")
				}
				if !strings.Contains(w.Body.String(), "Last observed state; verify current state") || strings.Contains(w.Body.String(), "extension operation accepted") {
					t.Error("DISABLE partial failure misreported")
				}
				return
			}
			item, err := f.svc.Get(context.Background(), metadataRecoveryID)
			metadataRecoveryCheck(t, err)
			if item.Enabled || item.Routed || item.ConfigurationRev != 1 {
				t.Error("DISABLE state/revision")
			}
			var count int
			metadataRecoveryCheck(t, f.db.QueryRow("SELECT count(*) FROM audit_events WHERE action='extension.disable' AND resource_id=$1", metadataRecoveryID).Scan(&count))
			if count != 1 {
				t.Error("DISABLE audit count")
			}
			for table, want := range before {
				if table != "extension_instances" && table != "audit_events" && after[table] != want {
					t.Error("DISABLE unrelated table changed", table)
				}
			}
		})
	}
}

func metadataRecoveryPreview(t *testing.T, f *metadataRecoveryFixture, operation string) (url.Values, string) {
	t.Helper()
	before := targetUISnapshot(t, f.db)
	w := f.request("POST", metadataRecoveryAlias, url.Values{"action": {operation + "-preview"}})
	// Nonfatal expected-view RED allows existing forms to exercise service guards.
	metadataRecoveryDocument(t, w)
	after := targetUISnapshot(t, f.db)
	for table, want := range before {
		if table != "extension_operation_previews" && after[table] != want {
			t.Error("PREVIEW changed nonpreview table", table)
		}
	}
	if after["extension_operation_previews"] == before["extension_operation_previews"] {
		t.Fatal("PREVIEW not issued; downstream confirmation paths blocked")
	}
	form, v, confirmation := updateForm(t, w.Body.String(), operation+"-apply")
	if updateAttr(form, "action") != extensionDetailActionURL(metadataRecoveryAlias, "dark") || v.Get("confirmation") != "" || len(v.Get("preview_id")) != 29 || !strings.HasPrefix(v.Get("preview_id"), "extp_") || len(confirmation) != 40 || !strings.HasPrefix(confirmation, "confirm-") {
		t.Error("PREVIEW native identity/blank confirmation contract")
	}
	v.Set("confirmation", confirmation)
	return v, confirmation
}
func TestExtensionMetadataRecoveryConfirmedActions(t *testing.T) {
	for _, operation := range []string{"secrets-delete", "uninstall"} {
		t.Run(operation, func(t *testing.T) {
			f := newMetadataRecoveryFixture(t)
			if operation == "secrets-delete" {
				actor := audit.ActorRef{Type: "local_admin", ID: "fixture"}
				input := extensionsadmin.ConfigureInput{Secrets: map[string]string{"retained.key": "PRIVATE-retained-secret"}}
				p, err := f.svc.PreviewConfigure(context.Background(), actor, metadataRecoveryID, input)
				metadataRecoveryCheck(t, err)
				_, err = f.svc.ApplyConfigure(context.Background(), actor, metadataRecoveryID, p.ID, p.Confirmation, input)
				metadataRecoveryCheck(t, err)
				_, err = f.db.Exec("UPDATE extension_instances SET secret_slots_json='[]'::jsonb WHERE instance_id=$1", metadataRecoveryID)
				metadataRecoveryCheck(t, err)
			}
			f.corrupt(t, strings.Replace(metadataRecoveryRaw("string", ""), extensionsadmin.MetadataSchema, "invalid", 1))
			sentinel, err := f.svc.Get(context.Background(), metadataRecoveryOther)
			metadataRecoveryCheck(t, err)
			v, confirmation := metadataRecoveryPreview(t, f, operation)
			beforeItem, e := f.svc.Get(context.Background(), metadataRecoveryID)
			metadataRecoveryCheck(t, e)
			for _, guard := range []string{"confirmation", "actor", "target", "revision", "expiry", "confirmation-hash", "enabled", "routed"} {
				t.Run(guard, func(t *testing.T) {
					var originalHash string
					metadataRecoveryCheck(t, f.db.QueryRow("SELECT confirmation_sha256 FROM extension_operation_previews WHERE id=$1", v.Get("preview_id")).Scan(&originalHash))
					values := metadataRecoveryValues(v)
					id := metadataRecoveryAlias
					oldHandler := f.handler
					oldNow := f.now
					switch guard {
					case "confirmation":
						values.Set("confirmation", "wrong")
					case "actor":
						b := f.bound
						b.Session.IdentityRefID = "other-admin"
						f.handler = f.withBound(b)
					case "target":
						id = metadataRecoveryOther
					case "revision":
						_, err = f.db.Exec("UPDATE extension_instances SET configuration_revision=configuration_revision+1 WHERE instance_id=$1", metadataRecoveryID)
					case "expiry":
						f.now = f.now.Add(16 * time.Minute)
					case "confirmation-hash":
						_, err = f.db.Exec("UPDATE extension_operation_previews SET confirmation_sha256=$1 WHERE id=$2", strings.Repeat("0", 64), v.Get("preview_id"))
					case "enabled":
						_, err = f.db.Exec("UPDATE extension_instances SET enabled=true WHERE instance_id=$1", metadataRecoveryID)
					case "routed":
						_, err = f.db.Exec("UPDATE extension_instances SET enabled=true,routed=true WHERE instance_id=$1", metadataRecoveryID)
					}
					metadataRecoveryCheck(t, err)
					before := targetUISnapshot(t, f.db)
					w := f.request("POST", id, values)
					if w.Code != 200 || strings.Contains(w.Body.String(), "extension operation accepted") || !strings.Contains(w.Body.String(), `role="alert"`) {
						t.Error("GUARD denial response", guard, w.Code)
					}
					metadataRecoveryUnchanged(t, f, before, 0)
					f.handler = oldHandler
					f.now = oldNow
					switch guard {
					case "revision":
						_, err = f.db.Exec("UPDATE extension_instances SET configuration_revision=configuration_revision-1 WHERE instance_id=$1", metadataRecoveryID)
					case "confirmation-hash":
						_, err = f.db.Exec("UPDATE extension_operation_previews SET confirmation_sha256=$1 WHERE id=$2", originalHash, v.Get("preview_id"))
					case "enabled", "routed":
						_, err = f.db.Exec("UPDATE extension_instances SET enabled=false,routed=false WHERE instance_id=$1", metadataRecoveryID)
					}
					metadataRecoveryCheck(t, err)
				})
			}
			v.Set("confirmation", confirmation)
			before := targetUISnapshot(t, f.db)
			w := f.request("POST", metadataRecoveryAlias, v)
			if operation == "uninstall" {
				if w.Code != 200 || !strings.Contains(w.Body.String(), "extension uninstalled") || strings.Contains(w.Body.String(), `name="field.`) {
					t.Error("UNINSTALL terminal receipt")
				}
				if _, err = f.svc.Get(context.Background(), metadataRecoveryID); !errors.Is(err, extensionsadmin.ErrNotFound) {
					t.Error("UNINSTALL row remains")
				}
			} else {
				metadataRecoveryDocument(t, w)
				var count int
				metadataRecoveryCheck(t, f.db.QueryRow("SELECT count(*) FROM extension_secrets WHERE instance_id=$1", metadataRecoveryID).Scan(&count))
				if count != 0 {
					t.Error("DELETE retained secret remains")
				}
				item, e := f.svc.Get(context.Background(), metadataRecoveryID)
				metadataRecoveryCheck(t, e)
				if item.ConfigurationRev != beforeItem.ConfigurationRev+1 || item.TestedRevision != 0 {
					t.Error("DELETE revision")
				}
			}
			var audits int
			auditAction := "extension.secrets.delete"
			if operation == "uninstall" {
				auditAction = "extension.uninstall"
			}
			metadataRecoveryCheck(t, f.db.QueryRow("SELECT count(*) FROM audit_events WHERE action=$1 AND resource_id=$2", auditAction, metadataRecoveryID).Scan(&audits))
			if audits != 1 {
				t.Error("SUCCESS audit count")
			}
			after := targetUISnapshot(t, f.db)
			for _, table := range []string{"tokens", "sessions", "identity_refs", "role_bindings"} {
				if after[table] != before[table] {
					t.Error("SUCCESS identity mutation", table)
				}
			}
			got, err := f.svc.Get(context.Background(), metadataRecoveryOther)
			metadataRecoveryCheck(t, err)
			if !reflect.DeepEqual(sentinel, got) {
				t.Error("SUCCESS sentinel changed")
			}
			var count int
			query := "SELECT count(*) FROM extension_operation_previews WHERE id=$1 AND consumed_at IS NOT NULL"
			wantCount := 1
			if operation == "uninstall" {
				query = "SELECT count(*) FROM extension_operation_previews WHERE id=$1"
				wantCount = 0
			}
			metadataRecoveryCheck(t, f.db.QueryRow(query, v.Get("preview_id")).Scan(&count))
			if count != wantCount {
				t.Error("SUCCESS preview not consumed")
			}
			replay := f.request("POST", metadataRecoveryAlias, v)
			if operation == "uninstall" && replay.Code != 404 || operation != "uninstall" && strings.Contains(replay.Body.String(), "extension operation accepted") {
				t.Error("REPLAY accepted")
			}
			metadataRecoveryUnchanged(t, f, after, 0)
		})
	}
}

func TestExtensionMetadataRecoveryRestoration(t *testing.T) {
	for _, kind := range []string{"outstanding-update", "rollback", "invalid-previous", "wrong-confirmation"} {
		t.Run(kind, func(t *testing.T) {
			f := newMetadataRecoveryFixture(t)
			target := url.Values{"action": {"update-preview"}, "artifact_pin": {"sha256:" + strings.Repeat("5", 64)}, "manifest_sha256": {strings.Repeat("6", 64)}, "grant_sha256": {strings.Repeat("7", 64)}, "session_sha256": {strings.Repeat("8", 64)}}
			preview := f.request("POST", metadataRecoveryAlias, target)
			v, confirmation := configurationActionForm(t, preview.Body.String(), "update-apply")
			v.Set("confirmation", confirmation)
			if kind != "outstanding-update" {
				w := f.request("POST", metadataRecoveryAlias, v)
				if w.Code != 200 || !strings.Contains(w.Body.String(), "extension operation accepted") {
					t.Fatal("SETUP real update failed")
				}
			}
			f.corrupt(t, metadataRecoveryRaw("unknown", ""))
			if kind == "invalid-previous" {
				_, err := f.db.Exec(`UPDATE extension_instances SET previous_version_json=jsonb_set(previous_version_json,'{metadata,schema}','"invalid"') WHERE instance_id=$1`, metadataRecoveryID)
				metadataRecoveryCheck(t, err)
			}
			before := targetUISnapshot(t, f.db)
			if kind != "outstanding-update" {
				item, err := f.svc.Get(context.Background(), metadataRecoveryID)
				metadataRecoveryCheck(t, err)
				v = url.Values{"action": {"rollback"}, "confirmation": {"rollback " + item.ExtensionID + " to " + item.PreviousArtifact}}
			}
			if kind == "wrong-confirmation" {
				v.Set("confirmation", "wrong")
			}
			w := f.request("POST", metadataRecoveryAlias, v)
			if kind == "wrong-confirmation" {
				metadataRecoveryDocument(t, w)
				metadataRecoveryUnchanged(t, f, before, 0)
				if strings.Contains(w.Body.String(), "extension operation accepted") || !strings.Contains(w.Body.String(), "extension confirmation rejected") || !strings.Contains(w.Body.String(), `role="alert"`) {
					t.Error("ROLLBACK wrong phrase accepted or not reported")
				}
				return
			}
			if kind == "invalid-previous" {
				metadataRecoveryDocument(t, w)
				metadataRecoveryUnchanged(t, f, before, 0)
				if strings.Contains(w.Body.String(), "extension operation accepted") {
					t.Error("ROLLBACK invalid previous accepted")
				}
				return
			}
			if w.Code != 200 || !strings.Contains(w.Body.String(), `id="configuration"`) || !strings.Contains(w.Body.String(), "extension operation accepted") || strings.Contains(w.Body.String(), metadataRecoveryCanary) {
				t.Error("RESTORE did not return valid normal detail")
			}
			item, err := f.svc.Get(context.Background(), metadataRecoveryID)
			metadataRecoveryCheck(t, err)
			wantRev := int64(2)
			wantPin := target.Get("artifact_pin")
			action := "extension.update"
			if kind == "rollback" {
				wantRev = 3
				wantPin = "sha256:" + strings.Repeat("1", 64)
				action = "extension.rollback"
			}
			if item.ConfigurationRev != wantRev || item.ArtifactPin != wantPin || item.Enabled || item.Routed {
				t.Error("RESTORE state")
			}
			var count int
			metadataRecoveryCheck(t, f.db.QueryRow("SELECT count(*) FROM audit_events WHERE action=$1 AND resource_id=$2", action, metadataRecoveryID).Scan(&count))
			if count != 1 {
				t.Error("RESTORE audit")
			}
			after := targetUISnapshot(t, f.db)
			for _, table := range []string{"extension_secrets", "tokens", "sessions", "identity_refs", "role_bindings"} {
				if after[table] != before[table] {
					t.Error("RESTORE unrelated mutation", table)
				}
			}
			if len(f.runtime.calls) != 0 {
				t.Error("RESTORE runtime called")
			}
		})
	}
}
func TestExtensionMetadataRecoveryHealthyAndTransport(t *testing.T) {
	f := newMetadataRecoveryFixture(t)
	w := f.request("POST", metadataRecoveryAlias, url.Values{"action": {"configure-preview"}, "field.config.text": {"submitted-<script>"}})
	_, v, confirmation := updateForm(t, w.Body.String(), "configure-apply")
	if v.Get("field.config.text") != "submitted-<script>" {
		t.Error("HEALTHY submitted Fields lost")
	}
	before := targetUISnapshot(t, f.db)
	v.Set("confirmation", "wrong")
	denied := f.request("POST", metadataRecoveryAlias, v)
	_, restored, _ := updateForm(t, denied.Body.String(), "configure-preview")
	if restored.Get("field.config.text") != "" {
		t.Error("HEALTHY denial did not restore stored Fields")
	}
	metadataRecoveryUnchanged(t, f, before, 0)
	v.Set("confirmation", confirmation)
	v.Set("csrf_token", metadataRecoveryCSRF)
	r := formReq("POST", extensionDetailActionURL(metadataRecoveryAlias, "dark"), v, "")
	withIdentityCookies(r, "metadata-recovery-session", metadataRecoveryCSRF)
	probe := &detailResponseProbe{header: make(http.Header), failure: errors.New("PRIVATE-transport")}
	f.handler.ServeHTTP(probe, r)
	item, err := f.svc.Get(context.Background(), metadataRecoveryID)
	metadataRecoveryCheck(t, err)
	if item.ConfigurationRev != 2 || item.Configuration["config.text"] != "submitted-<script>" {
		t.Error("TRANSPORT committed configure missing")
	}
	if probe.writes != 1 || strings.Contains(probe.body.String(), "rollback") || strings.Contains(probe.body.String(), "retry") {
		t.Error("TRANSPORT retried or false rollback")
	}
	// Existing HTML helper, not a future component symbol: alias/theme preserved.
	root, err := html.Parse(strings.NewReader(w.Body.String()))
	metadataRecoveryCheck(t, err)
	walkUpdateHTML(root, func(n *html.Node) {
		if n.Data == "form" && updateAttr(n, "action") != extensionDetailActionURL(metadataRecoveryAlias, "dark") {
			t.Error("HEALTHY alias/theme lost")
		}
	})
}

func TestExtensionMetadataRecoveryKindActions(t *testing.T) {
	for _, operation := range []string{"secrets-delete", "uninstall"} {
		t.Run(operation, func(t *testing.T) {
			f := newMetadataRecoveryFixture(t)
			f.corrupt(t, metadataRecoveryRaw("unknown", ""))
			v, _ := metadataRecoveryPreview(t, f, operation)
			w := f.request("POST", metadataRecoveryAlias, v)
			if operation == "uninstall" {
				if w.Code != 200 || !strings.Contains(w.Body.String(), "extension uninstalled") {
					t.Error("kind uninstall terminal")
				}
			} else {
				metadataRecoveryDocument(t, w)
			}
			if len(f.runtime.calls) != 0 {
				t.Error("kind recovery entered runtime")
			}
		})
	}
}
func TestExtensionMetadataRecoveryAdditionalDenials(t *testing.T) {
	f := newMetadataRecoveryFixture(t)
	actor := audit.ActorRef{Type: "local_admin", ID: "fixture"}
	input := extensionsadmin.ConfigureInput{Secrets: map[string]string{"retained.key": "PRIVATE-retained-value"}}
	p, err := f.svc.PreviewConfigure(context.Background(), actor, metadataRecoveryID, input)
	metadataRecoveryCheck(t, err)
	_, err = f.svc.ApplyConfigure(context.Background(), actor, metadataRecoveryID, p.ID, p.Confirmation, input)
	metadataRecoveryCheck(t, err)
	f.corrupt(t, metadataRecoveryRaw("unknown", ""))
	t.Run("disabled-noop", func(t *testing.T) {
		before := targetUISnapshot(t, f.db)
		w := f.request("POST", metadataRecoveryID, url.Values{"action": {"disable"}})
		metadataRecoveryDocument(t, w)
		metadataRecoveryUnchanged(t, f, before, 0)
	})
	t.Run("uninstall-nonzero-secrets", func(t *testing.T) {
		v, _ := metadataRecoveryPreview(t, f, "uninstall")
		before := targetUISnapshot(t, f.db)
		w := f.request("POST", metadataRecoveryAlias, v)
		metadataRecoveryDocument(t, w)
		metadataRecoveryUnchanged(t, f, before, 0)
		if strings.Contains(w.Body.String(), "extension operation accepted") || !strings.Contains(w.Body.String(), "extension state conflict") {
			t.Error("uninstall nonzero secrets denial")
		}
	})
	t.Run("wrongrollback", func(t *testing.T) {
		before := targetUISnapshot(t, f.db)
		w := f.request("POST", metadataRecoveryID, url.Values{"action": {"rollback"}, "confirmation": {"wrong"}})
		metadataRecoveryDocument(t, w)
		metadataRecoveryUnchanged(t, f, before, 0)
		if !strings.Contains(w.Body.String(), "extension confirmation rejected") {
			t.Error("rollback denial")
		}
	})
}
func TestExtensionMetadataRecoveryByteBound(t *testing.T) {
	f := newMetadataRecoveryFixture(t)
	m := extensionsadmin.Metadata{Schema: extensionsadmin.MetadataSchema}
	for i := 0; i < 64; i++ {
		m.Fields = append(m.Fields, extensionsadmin.Field{Name: fmt.Sprintf("field.n%d", i), Label: "Valid", Kind: extensionsadmin.FieldString, Default: strings.Repeat("x", 1100)})
	}
	raw, err := json.Marshal(m)
	metadataRecoveryCheck(t, err)
	if len(raw) <= 64<<10 {
		t.Fatal("SETUP byte boundary not reached")
	}
	f.corrupt(t, string(raw))
	before := targetUISnapshot(t, f.db)
	w := f.request("GET", metadataRecoveryID, nil)
	metadataRecoveryDocument(t, w)
	metadataRecoveryUnchanged(t, f, before, 0)
	if strings.Contains(w.Body.String(), strings.Repeat("x", 100)) {
		t.Error("oversize default reflected")
	}
}
