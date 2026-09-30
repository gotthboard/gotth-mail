package httpui

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"forgejo/gotthboard/gotth-mail/internal/authn"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	"forgejo/gotthboard/gotth-mail/internal/admin"
	"forgejo/gotthboard/gotth-mail/internal/audit"
	"forgejo/gotthboard/gotth-mail/internal/authz"
	"forgejo/gotthboard/gotth-mail/internal/extensionsadmin"
	"forgejo/gotthboard/gotth-mail/internal/identity"
	"forgejo/gotthboard/gotth-mail/internal/rolebinding"
	"forgejo/gotthboard/gotth-mail/internal/store"
	"forgejo/gotthboard/gotth-mail/internal/testpg"
)

// Entire durable rows stay in memory only: failures name tables, never contents.
func targetUISnapshot(t *testing.T, db *sql.DB) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, table := range []string{"extension_instances", "extension_secrets", "extension_operation_previews", "audit_events", "tokens", "sessions", "identity_refs", "role_bindings"} {
		var rows string
		if err := db.QueryRow("SELECT COALESCE(jsonb_agg(v ORDER BY v::text)::text,'[]') FROM (SELECT to_jsonb(r) AS v FROM " + table + " r) q").Scan(&rows); err != nil {
			t.Fatal("snapshot query failed for " + table)
		}
		out[table] = rows
	}
	return out
}

// No network/process runtime is installed; count every interface entry, not Start alone.
type targetUIRuntime struct{ calls int }

func (r *targetUIRuntime) Start(context.Context, extensionsadmin.Instance, map[string][]byte) error {
	r.calls++
	return fmt.Errorf("unexpected runtime")
}
func (r *targetUIRuntime) Probe(context.Context, extensionsadmin.Instance) (extensionsadmin.Health, error) {
	r.calls++
	return extensionsadmin.Health{}, fmt.Errorf("unexpected runtime")
}
func (r *targetUIRuntime) AdmitRouting(context.Context, extensionsadmin.Instance) error {
	r.calls++
	return fmt.Errorf("unexpected runtime")
}
func (r *targetUIRuntime) RevokeRouting(context.Context, extensionsadmin.Instance) error {
	r.calls++
	return fmt.Errorf("unexpected runtime")
}
func (r *targetUIRuntime) Stop(context.Context, extensionsadmin.Instance) error {
	r.calls++
	return fmt.Errorf("unexpected runtime")
}

func TestExtensionTargetConfigureReducedScope(t *testing.T) { targetUIReducedScope(t, "configure") }
func TestExtensionTargetUpdateReducedScope(t *testing.T)    { targetUIReducedScope(t, "update") }

func TestExtensionTargetDeleteReducedScope(t *testing.T) { targetUIReducedScope(t, "secrets-delete") }

func TestExtensionTargetUninstallReducedScope(t *testing.T) { targetUIReducedScope(t, "uninstall") }

func targetUIReducedScope(t *testing.T, operation string) {
	db := testpg.DB(t, store.MigrateSQL)
	var version int
	if err := db.QueryRow("SELECT current_setting('server_version_num')::int").Scan(&version); err != nil {
		t.Fatal(err)
	}
	t.Logf("PostgreSQL=%d", version)
	check := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal("fixture operation failed")
		}
	}
	random := func() string { b := make([]byte, 32); _, err := rand.Read(b); check(err); return hex.EncodeToString(b) }
	runtime := &targetUIRuntime{}
	svc, err := extensionsadmin.NewService(db, []byte(random()[:32]), runtime)
	check(err)
	now := time.Date(2026, 9, 27, 12, 0, 0, 0, time.UTC)
	svc.Now = func() time.Time { return now }
	ids, err := identity.NewSQLService(context.Background(), db, "example.test")
	check(err)
	const a = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	const b = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
	for i, id := range []string{a, b, "cccccccc-cccc-4ccc-8ccc-cccccccccccc"} {
		_, err := svc.Install(context.Background(), audit.ActorRef{Type: "local_admin", ID: "fixture"}, extensionsadmin.InstallRequest{InstanceID: id, ExtensionID: fmt.Sprintf("notification.target%d", i), Repository: "https://github.com/gotthboard/gotth-extension-target", ArtifactPin: "sha256:" + random(), ManifestDigest: random(), GrantDigest: random(), SessionDigest: random(), Metadata: extensionsadmin.Metadata{Schema: extensionsadmin.MetadataSchema, Fields: []extensionsadmin.Field{{Name: "config.text", Label: "Text", Kind: extensionsadmin.FieldString}}}})
		check(err)
	}
	if operation == "secrets-delete" {
		for _, id := range []string{a, b} {
			// Real encrypted retained slot no longer in current metadata/slot list.
			if _, err := db.Exec("UPDATE extension_instances SET secret_slots_json='[\"retained.key\"]'::jsonb WHERE instance_id=$1", id); err != nil {
				t.Fatal("slot fixture")
			}
			input := extensionsadmin.ConfigureInput{Secrets: map[string]string{"retained.key": random()}}
			p, err := svc.PreviewConfigure(context.Background(), audit.ActorRef{Type: "local_admin", ID: "fixture"}, id, input)
			check(err)
			_, err = svc.ApplyConfigure(context.Background(), audit.ActorRef{Type: "local_admin", ID: "fixture"}, id, p.ID, p.Confirmation, input)
			check(err)
			if _, err = db.Exec("UPDATE extension_instances SET secret_slots_json='[]'::jsonb WHERE instance_id=$1", id); err != nil {
				t.Fatal("retained slot fixture")
			}
		}
	}
	token := random()
	check(ids.AddTokenWithScopes("target-owner", "api_token", token, "ops:admin:"+a, "ops:admin:"+b))
	original, err := ids.AuthenticateBearer("Bearer "+token, "api_token")
	check(err)
	handler := HandlerWithAdminIdentitySessionsAndExtensions(admin.NewStore(), ids, authz.StaticAuthorizer{}, nil, func() time.Time { return now }, svc)
	request := func(method, id string, values url.Values) *httptest.ResponseRecorder {
		req := formReq(method, "/admin/extensions/"+id, values, "Bearer "+token)
		res := httptest.NewRecorder()
		handler.ServeHTTP(res, req)
		if strings.Contains(res.Body.String(), token) {
			t.Fatal("credential reflected")
		}
		return res
	}
	values := url.Values{"action": {operation + "-preview"}, "field.config.text": {"accepted B value"}}
	if operation == "update" {
		values = url.Values{"action": {"update-preview"}, "artifact_pin": {"sha256:" + strings.Repeat("5", 64)}, "manifest_sha256": {strings.Repeat("6", 64)}, "grant_sha256": {strings.Repeat("7", 64)}, "session_sha256": {strings.Repeat("8", 64)}}
	}
	preview := request("POST", b, values)
	if preview.Code != 200 || !strings.Contains(preview.Body.String(), "extension operation accepted") {
		t.Fatal("legitimate B preview rejected")
	}
	apply, confirmation := configurationActionForm(t, preview.Body.String(), operation+"-apply")
	apply.Set("confirmation", confirmation)
	if apply.Get("preview_id") == "" || confirmation == "" {
		t.Fatal("preview binding absent")
	}
	check(ids.AddTokenWithScopes("target-owner", "api_token", token, "ops:admin:"+a))
	reduced, err := ids.AuthenticateBearer("Bearer "+token, "api_token")
	check(err)
	if original.Type != reduced.Type || original.ID != reduced.ID || !reflect.DeepEqual(reduced.Scopes, []string{"ops:admin:" + a}) {
		t.Fatal("same actor scope reduction not established")
	}
	// Reload is a persistence control, not a replacement for the live-map update above.
	reloaded, err := identity.NewSQLService(context.Background(), db, "example.test")
	check(err)
	persisted, err := reloaded.AuthenticateBearer("Bearer "+token, "api_token")
	check(err)
	if !reflect.DeepEqual(reduced, persisted) {
		t.Fatal("scope replacement not persisted")
	}
	before := targetUISnapshot(t, db)
	if request("GET", a, nil).Code != 200 || request("POST", b, apply).Code != 403 {
		t.Fatal("A allowed/B denied control failed")
	}
	res := request("POST", a, apply)
	after := targetUISnapshot(t, db)
	for table, rows := range before {
		if rows != after[table] {
			t.Errorf("cross-target denial changed authoritative table %s", table)
		}
	}
	if res.Code != 200 || !strings.Contains(res.Body.String(), extensionsadmin.ErrConfirmation.Error()) || strings.Contains(res.Body.String(), "extension operation accepted") {
		t.Error("cross-target Apply did not retain UI confirmation-denial contract")
	}
	if strings.Contains(res.Body.String(), b) || strings.Contains(res.Body.String(), "accepted B value") {
		t.Error("denial projected B target")
	}
	if runtime.calls != 0 {
		t.Error("runtime called")
	}
	if t.Failed() {
		return
	}
	old := token
	token = random()
	check(ids.AddTokenWithScopes("target-owner", "api_token", token, "ops:admin:"+a))
	rotated, err := ids.AuthenticateBearer("Bearer "+token, "api_token")
	check(err)
	if rotated.ID != original.ID || rotated.Type != original.Type {
		t.Fatal("rotation changed actor")
	}
	beforeRotationDenial := targetUISnapshot(t, db)
	req := formReq("POST", "/admin/extensions/"+b, apply, "Bearer "+old)
	staleResponse := httptest.NewRecorder()
	handler.ServeHTTP(staleResponse, req)
	if staleResponse.Code != 401 || !reflect.DeepEqual(beforeRotationDenial, targetUISnapshot(t, db)) {
		t.Fatal("old credential accepted or denial mutated state")
	}
	if request("GET", a, nil).Code != 200 || request("POST", b, apply).Code != 403 {
		t.Fatal("rotated narrow credential authority")
	}
	res = request("POST", a, apply)
	if res.Code != 200 || !strings.Contains(res.Body.String(), extensionsadmin.ErrConfirmation.Error()) || !reflect.DeepEqual(beforeRotationDenial, targetUISnapshot(t, db)) {
		t.Fatal("rotated cross-target denial changed state")
	}
	check(ids.AddTokenWithScopes("target-owner", "api_token", token, "ops:admin:"+a, "ops:admin:"+b))
	unrelated, err := svc.Get(context.Background(), a)
	check(err)
	res = request("POST", b, apply)
	afterA, err := svc.Get(context.Background(), a)
	check(err)
	if !reflect.DeepEqual(unrelated, afterA) {
		t.Fatal("success changed unrelated instance")
	}
	afterSuccess := targetUISnapshot(t, db)
	replay := request("POST", b, apply)
	if operation == "uninstall" {
		if replay.Code != 404 {
			t.Error("uninstall replay status")
		}
	} else if replay.Code != 200 || !strings.Contains(replay.Body.String(), extensionsadmin.ErrConfirmation.Error()) {
		t.Error("preview replay accepted")
	}
	if !reflect.DeepEqual(afterSuccess, targetUISnapshot(t, db)) {
		t.Fatal("replay changed durable state")
	}
	if operation == "uninstall" {
		if res.Code != 200 || !strings.Contains(res.Body.String(), "extension uninstalled") {
			t.Fatal("uninstall failed")
		}
		var remaining int
		check(db.QueryRow("SELECT count(*) FROM extension_instances WHERE instance_id=$1", b).Scan(&remaining))
		if remaining != 0 {
			t.Fatal("uninstall target survived")
		}
		check(db.QueryRow("SELECT count(*) FROM extension_operation_previews WHERE instance_id=$1", b).Scan(&remaining))
		if remaining != 0 {
			t.Fatal("preview cascade absent")
		}
		if request("GET", b, nil).Code != 404 || request("GET", a, nil).Code != 200 {
			t.Fatal("wrong post-uninstall target existence")
		}
		if runtime.calls != 0 {
			t.Fatal("runtime called")
		}
		return
	}
	if res.Code != 200 || !strings.Contains(res.Body.String(), "extension operation accepted") {
		t.Fatal("restored B authority cannot reuse unchanged preview")
	}
	item, err := svc.Get(context.Background(), b)
	check(err)
	expectedRev := int64(2)
	if operation == "secrets-delete" {
		expectedRev = 3
		var count int
		check(db.QueryRow("SELECT count(*) FROM extension_secrets WHERE instance_id=$1", b).Scan(&count))
		if count != 0 {
			t.Fatal("retained secrets survived deletion")
		}
	}
	if item.ConfigurationRev != expectedRev || operation == "configure" && item.Configuration["config.text"] != "accepted B value" || operation == "update" && item.ArtifactPin != "sha256:"+strings.Repeat("5", 64) {
		t.Fatal("correct target result absent")
	}
	if runtime.calls != 0 {
		t.Fatal("runtime called")
	}
}

// Real SQLStore cookie/CSRF and global-role state, not a per-extension OIDC role.
func TestExtensionTargetCookieGlobalRole(t *testing.T) {
	for _, op := range []string{"configure", "update", "secrets-delete", "uninstall"} {
		t.Run(op, func(t *testing.T) {
			check := func(err error) {
				t.Helper()
				if err != nil {
					t.Fatalf("fixture error type=%T", err)
				}
			}
			db := testpg.DB(t, store.MigrateSQL)
			run := func(q string, args ...any) { t.Helper(); _, err := db.Exec(q, args...); check(err) }
			now := time.Date(2026, 9, 28, 23, 0, 0, 0, time.UTC)
			uuid := func(n int) string { return fmt.Sprintf("aabbccdd-0000-4000-8000-%012d", n) }
			domain, mailbox, who := uuid(1), uuid(2), uuid(3)
			const sid = "target-cookie-session"
			const csrf = "target-cookie-csrf"
			run("INSERT INTO domains(id,name,created_at,updated_at) VALUES ($1,'example.test',$2,$2)", domain, now)
			run("INSERT INTO mailboxes(id,domain_id,local_part,created_at,updated_at) VALUES ($1,$2,'admin',$3,$3)", mailbox, domain, now)
			run("INSERT INTO identity_refs(id,provider,issuer,subject,mailbox_id,created_at,updated_at) VALUES ($1,'authentik','https://identity.example.test/application/o/gotth-mail/','admin',$2,$3,$3)", who, mailbox, now)
			run("INSERT INTO sessions(id,identity_ref_id,csrf_secret_hash,auth_method,created_at,expires_at,last_seen_at) VALUES ($1,$2,$3,'oidc',$4,$5,$4)", sid, who, csrfHash(csrf), now.Add(-time.Minute), now.Add(time.Hour))
			roles := rolebinding.Service{DB: db, Now: func() time.Time { return now }}
			changeRole := func(operation string) {
				t.Helper()
				req := rolebinding.Request{Operation: operation, Issuer: "https://identity.example.test/application/o/gotth-mail/", Subject: "admin", Mailbox: "admin@example.test", Role: rolebinding.RoleGlobalAdmin}
				p, err := roles.Preview(context.Background(), req)
				check(err)
				result, err := roles.Apply(context.Background(), req, p.PlanID)
				check(err)
				if !result.Changed {
					t.Fatal("role binding unchanged")
				}
			}
			changeRole(rolebinding.OperationGrant)
			runtime := &targetUIRuntime{}
			svc, err := extensionsadmin.NewService(db, []byte(strings.Repeat("k", 32)), runtime)
			check(err)
			svc.Now = func() time.Time { return now }
			a, b := uuid(10), uuid(11)
			for i, id := range []string{a, b} {
				_, err := svc.Install(context.Background(), audit.ActorRef{Type: "local_admin", ID: "fixture"}, extensionsadmin.InstallRequest{InstanceID: id, ExtensionID: fmt.Sprintf("notification.cookie%d", i), Repository: "https://github.com/gotthboard/gotth-extension-target", ArtifactPin: "sha256:" + strings.Repeat("1", 64), ManifestDigest: strings.Repeat("2", 64), GrantDigest: strings.Repeat("3", 64), SessionDigest: strings.Repeat("4", 64), Metadata: extensionsadmin.Metadata{Schema: extensionsadmin.MetadataSchema}})
				check(err)
			}
			if op == "secrets-delete" {
				actor := audit.ActorRef{Type: "local_admin", ID: "fixture"}
				for _, id := range []string{a, b} {
					run("UPDATE extension_instances SET secret_slots_json='[\"retained.key\"]' WHERE instance_id=$1", id)
					input := extensionsadmin.ConfigureInput{Secrets: map[string]string{"retained.key": "synthetic-retained"}}
					p, err := svc.PreviewConfigure(context.Background(), actor, id, input)
					check(err)
					_, err = svc.ApplyConfigure(context.Background(), actor, id, p.ID, p.Confirmation, input)
					check(err)
					run("UPDATE extension_instances SET secret_slots_json='[]' WHERE instance_id=$1", id)
				}
			}
			h := HandlerWithAdminIdentitySessionsAndExtensions(admin.NewStore(), identity.NewService("example.test"), authz.StaticAuthorizer{}, authn.SQLStore{DB: db}, func() time.Time { return now }, svc)
			request := func(id string, form url.Values, session, cookie, authorization string) *httptest.ResponseRecorder {
				r := formReq("POST", "/admin/extensions/"+id, form, authorization)
				if session != "" {
					r.AddCookie(&http.Cookie{Name: "gotth_mail_session", Value: session})
				}
				if cookie != "" {
					r.AddCookie(&http.Cookie{Name: "gotth_mail_csrf", Value: cookie})
				}
				w := httptest.NewRecorder()
				h.ServeHTTP(w, r)
				return w
			}
			values := url.Values{"action": {op + "-preview"}, "csrf_token": {csrf}}
			if op == "update" {
				values.Set("artifact_pin", "sha256:"+strings.Repeat("5", 64))
				values.Set("manifest_sha256", strings.Repeat("6", 64))
				values.Set("grant_sha256", strings.Repeat("7", 64))
				values.Set("session_sha256", strings.Repeat("8", 64))
			}
			w := request(b, values, sid, csrf, "")
			if w.Code != 200 || !strings.Contains(w.Body.String(), "extension operation accepted") {
				t.Fatalf("cookie preview status=%d", w.Code)
			}
			apply, confirmation := configurationActionForm(t, w.Body.String(), op+"-apply")
			apply.Set("confirmation", confirmation)
			if apply.Get("preview_id") == "" || confirmation == "" {
				t.Fatal("missing preview")
			}
			denied := func(id, session, cookie, authorization string, status int) {
				t.Helper()
				before := targetUISnapshot(t, db)
				w := request(id, apply, session, cookie, authorization)
				if w.Code != status {
					t.Errorf("denial status=%d want=%d", w.Code, status)
				}
				if !reflect.DeepEqual(before, targetUISnapshot(t, db)) {
					t.Error("cookie denial changed durable rows")
				}
				if runtime.calls != 0 {
					t.Error("runtime called")
				}
			}
			denied(b, "", "", "", 401)
			denied(b, sid, "", "", 401)
			denied(b, sid, "wrong", "", 401)
			denied(b, sid, csrf, "Bearer invalid", 401)
			saved := apply.Get("csrf_token")
			apply.Set("csrf_token", "wrong")
			denied(b, sid, csrf, "", 403)
			apply.Set("csrf_token", saved)
			changeRole(rolebinding.OperationRevoke)
			denied(a, sid, csrf, "", 403)
			denied(b, sid, csrf, "", 403)
			changeRole(rolebinding.OperationGrant)
			before := targetUISnapshot(t, db)
			w = request(a, apply, sid, csrf, "")
			if w.Code != 200 || !strings.Contains(w.Body.String(), extensionsadmin.ErrConfirmation.Error()) || !reflect.DeepEqual(before, targetUISnapshot(t, db)) {
				t.Error("cookie cross-target denial contract")
			}
			if t.Failed() {
				return
			}
			unrelated, err := svc.Get(context.Background(), a)
			check(err)
			var secretsA string
			check(db.QueryRow("SELECT COALESCE(jsonb_agg(to_jsonb(s) ORDER BY slot)::text,'[]') FROM extension_secrets s WHERE instance_id=$1", a).Scan(&secretsA))
			w = request(b, apply, sid, csrf, "")
			want := "extension operation accepted"
			if op == "uninstall" {
				want = "extension uninstalled"
			}
			if w.Code != 200 || !strings.Contains(w.Body.String(), want) {
				t.Fatal("restored global role cannot reuse preview")
			}
			if runtime.calls != 0 {
				t.Fatal("runtime called")
			}
			var count int
			check(db.QueryRow("SELECT count(*) FROM audit_events WHERE resource_id=$1 AND action=$2", b, map[string]string{"configure": "extension.configure", "update": "extension.update", "secrets-delete": "extension.secrets.delete", "uninstall": "extension.uninstall"}[op]).Scan(&count))
			if count != 1 {
				t.Error("audit not exactly once")
			}
			afterA, err := svc.Get(context.Background(), a)
			check(err)
			if !reflect.DeepEqual(unrelated, afterA) {
				t.Error("cookie success changed A")
			}
			var afterSecretsA string
			check(db.QueryRow("SELECT COALESCE(jsonb_agg(to_jsonb(s) ORDER BY slot)::text,'[]') FROM extension_secrets s WHERE instance_id=$1", a).Scan(&afterSecretsA))
			if afterSecretsA != secretsA {
				t.Error("cookie success changed A secrets")
			}
			if op == "uninstall" {
				check(db.QueryRow("SELECT count(*) FROM extension_instances WHERE instance_id=$1", b).Scan(&count))
				if count != 0 {
					t.Error("uninstall row survived")
				}
				check(db.QueryRow("SELECT count(*) FROM extension_operation_previews WHERE instance_id=$1", b).Scan(&count))
				if count != 0 {
					t.Error("cascade absent")
				}
			} else {
				item, err := svc.Get(context.Background(), b)
				check(err)
				expected := int64(2)
				if op == "secrets-delete" {
					expected = 3
					check(db.QueryRow("SELECT count(*) FROM extension_secrets WHERE instance_id=$1", b).Scan(&count))
					if count != 0 {
						t.Error("retained secret survived")
					}
				}
				if item.ConfigurationRev != expected {
					t.Error("revision not once")
				}
			}
			after := targetUISnapshot(t, db)
			w = request(b, apply, sid, csrf, "")
			if op == "uninstall" {
				if w.Code != 404 {
					t.Error("uninstall replay status")
				}
			} else if w.Code != 200 || !strings.Contains(w.Body.String(), extensionsadmin.ErrConfirmation.Error()) {
				t.Error("cookie replay accepted")
			}
			if !reflect.DeepEqual(after, targetUISnapshot(t, db)) {
				t.Error("cookie replay mutated rows")
			}
		})
	}
}
