package api

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"forgejo/gotthboard/gotth-mail/internal/audit"
	"forgejo/gotthboard/gotth-mail/internal/authz"
	"forgejo/gotthboard/gotth-mail/internal/extensionsadmin"
	"forgejo/gotthboard/gotth-mail/internal/identity"
	"forgejo/gotthboard/gotth-mail/internal/store"
	"forgejo/gotthboard/gotth-mail/internal/testpg"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"
)

type targetAPIRuntime struct{ calls int }

func (r *targetAPIRuntime) Start(context.Context, extensionsadmin.Instance, map[string][]byte) error {
	r.calls++
	return fmt.Errorf("unexpected runtime")
}
func (r *targetAPIRuntime) Probe(context.Context, extensionsadmin.Instance) (extensionsadmin.Health, error) {
	r.calls++
	return extensionsadmin.Health{}, fmt.Errorf("unexpected runtime")
}
func (r *targetAPIRuntime) AdmitRouting(context.Context, extensionsadmin.Instance) error {
	r.calls++
	return fmt.Errorf("unexpected runtime")
}
func (r *targetAPIRuntime) RevokeRouting(context.Context, extensionsadmin.Instance) error {
	r.calls++
	return fmt.Errorf("unexpected runtime")
}
func (r *targetAPIRuntime) Stop(context.Context, extensionsadmin.Instance) error {
	r.calls++
	return fmt.Errorf("unexpected runtime")
}

func apiTargetSnapshot(t *testing.T, db *sql.DB) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, table := range []string{"extension_instances", "extension_secrets", "extension_operation_previews", "audit_events", "tokens", "sessions", "identity_refs", "role_bindings"} {
		var row string
		if err := db.QueryRow("SELECT COALESCE(jsonb_agg(v ORDER BY v::text)::text,'[]') FROM (SELECT to_jsonb(r) v FROM " + table + " r) q").Scan(&row); err != nil {
			t.Fatal("snapshot " + table)
		}
		out[table] = row
	}
	return out
}
func TestExtensionAPITargetBinding(t *testing.T) {
	db := testpg.DB(t, store.MigrateSQL)
	check := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatalf("fixture error type=%T", err)
		}
	}
	random := func() string { b := make([]byte, 32); _, err := rand.Read(b); check(err); return hex.EncodeToString(b) }
	ids, err := identity.NewSQLService(context.Background(), db, "example.test")
	check(err)
	runtime := &targetAPIRuntime{}
	svc, err := extensionsadmin.NewService(db, []byte(random()[:32]), runtime)
	check(err)
	now := time.Date(2026, 9, 27, 12, 0, 0, 0, time.UTC)
	svc.Now = func() time.Time { return now }
	handler := (Server{Identity: ids, Authz: authz.StaticAuthorizer{}, Extensions: svc}).Handler()
	request := func(t *testing.T, id, action, token, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest("POST", "/api/v1/extensions/"+id+"/"+action, strings.NewReader(body))
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		if runtime.calls != 0 {
			t.Fatal("API runtime side effect")
		}
		if token != "" && strings.Contains(w.Body.String(), token) {
			t.Fatal("credential reflected")
		}
		return w
	}
	seq := 0
	for _, op := range []string{"configure", "update", "secrets/delete"} {
		for _, scope := range []string{"ops:admin:gotth-mail", "ops:admin"} {
			t.Run(op+"/"+scope, func(t *testing.T) {
				check := func(err error) {
					t.Helper()
					if err != nil {
						t.Fatalf("fixture error type=%T", err)
					}
				}
				random := func() string { b := make([]byte, 32); _, err := rand.Read(b); check(err); return hex.EncodeToString(b) }

				seq++
				a := fmt.Sprintf("aaaaaaaa-aaaa-4aaa-8aaa-%012x", seq)
				b := fmt.Sprintf("bbbbbbbb-bbbb-4bbb-8bbb-%012x", seq)
				metadata := extensionsadmin.Metadata{Schema: extensionsadmin.MetadataSchema}
				for i, id := range []string{a, b} {
					_, err := svc.Install(context.Background(), audit.ActorRef{Type: "local_admin", ID: "fixture"}, extensionsadmin.InstallRequest{InstanceID: id, ExtensionID: fmt.Sprintf("notification.api%d-%d", seq, i), Repository: "https://github.com/gotthboard/gotth-extension-target", ArtifactPin: "sha256:" + strings.Repeat("1", 64), ManifestDigest: strings.Repeat("2", 64), GrantDigest: strings.Repeat("3", 64), SessionDigest: strings.Repeat("4", 64), Metadata: metadata})
					check(err)
				}
				if op == "secrets/delete" {
					actor := audit.ActorRef{Type: "local_admin", ID: "fixture"}
					for _, id := range []string{a, b} {
						_, err := db.Exec("UPDATE extension_instances SET secret_slots_json='[\"retained.key\"]' WHERE instance_id=$1", id)
						check(err)
						input := extensionsadmin.ConfigureInput{Secrets: map[string]string{"retained.key": "synthetic-retained"}}
						p, err := svc.PreviewConfigure(context.Background(), actor, id, input)
						check(err)
						_, err = svc.ApplyConfigure(context.Background(), actor, id, p.ID, p.Confirmation, input)
						check(err)
						_, err = db.Exec("UPDATE extension_instances SET secret_slots_json='[]' WHERE instance_id=$1", id)
						check(err)
					}
				}
				token := random()
				check(ids.AddTokenWithScopes("api-target", "api_token", token, scope))
				previewBody := "{}"
				if op == "update" {
					data, err := json.Marshal(extensionsadmin.UpdateInput{ArtifactPin: "sha256:" + strings.Repeat("5", 64), ManifestDigest: strings.Repeat("6", 64), GrantDigest: strings.Repeat("7", 64), SessionDigest: strings.Repeat("8", 64), Metadata: metadata})
					check(err)
					previewBody = string(data)
				}
				w := request(t, b, op+"/preview", token, previewBody)
				if w.Code != 200 {
					t.Fatal("preview denied")
				}
				var p extensionsadmin.Preview
				check(json.Unmarshal(w.Body.Bytes(), &p))
				if p.ID == "" || p.Confirmation == "" {
					t.Fatal("preview absent")
				}
				bodyBytes, err := json.Marshal(map[string]any{"preview_id": p.ID, "confirmation": p.Confirmation})
				check(err)
				body := string(bodyBytes)
				denied := func(id, credential, body string, status int) {
					t.Helper()
					before := apiTargetSnapshot(t, db)
					w := request(t, id, op+"/apply", credential, body)
					if w.Code != status {
						t.Errorf("denial status=%d want=%d", w.Code, status)
					}
					after := apiTargetSnapshot(t, db)
					for table, rows := range before {
						if rows != after[table] {
							t.Errorf("denial changed %s", table)
						}
					}
					if strings.Contains(w.Body.String(), b) {
						t.Error("denial reflected B")
					}
				}
				denied(a, token, body, 409)
				denied("{"+a+"}", token, body, 409)
				denied("invalid", token, body, 409)
				denied(strings.Repeat("a", 65536), token, body, 409)
				denied(b, "", body, 401)
				denied(b, random(), body, 401)
				denied(b, token, body+"{}", 400)
				denied(b, token, strings.TrimSuffix(body, "}")+",\"expected_instance_id\":\""+b+"\"}", 400)
				// Supported replacement, not SQL behind an unchanged in-memory identity map.
				check(ids.AddTokenWithScopes("api-target", "api_token", token, "ops:admin:"+a))
				denied(a, token, body, 403)
				denied(b, token, body, 403)
				check(ids.AddTokenWithScopes("api-target", "api_token", token, "ops:admin:"+a, "ops:admin:"+b))
				denied(b, token, body, 403)
				check(ids.AddTokenWithScopes("api-target", "api_token", token, scope))
				// Same actor ID, new secret: old credential is dead, preview binding survives rotation.
				original, err := ids.AuthenticateBearer("Bearer "+token, "api_token")
				check(err)
				old := token
				token = random()
				check(ids.AddTokenWithScopes("api-target", "api_token", token, scope))
				rotated, err := ids.AuthenticateBearer("Bearer "+token, "api_token")
				check(err)
				if original.Type != rotated.Type || original.ID != rotated.ID {
					t.Fatal("rotation changed actor")
				}
				denied(b, old, body, 401)
				// Real parsed route aliases. Fresh preview per subsequent success.
				compact := strings.ReplaceAll(b, "-", "")
				var groups []string
				for i := 0; i < 32; i += 4 {
					groups = append(groups, compact[i:i+4])
				}
				unrelated, err := svc.Get(context.Background(), a)
				check(err)
				var secretsA string
				check(db.QueryRow("SELECT COALESCE(jsonb_agg(to_jsonb(s) ORDER BY slot)::text,'[]') FROM extension_secrets s WHERE instance_id=$1", a).Scan(&secretsA))
				for i, alias := range []string{strings.ToUpper(b), "{" + b + "}", compact, "{" + strings.Join(groups, "-") + "}"} {
					if i > 0 {
						if op == "update" {
							var target map[string]any
							check(json.Unmarshal([]byte(previewBody), &target))
							target["artifact_pin"] = "sha256:" + random()
							data, err := json.Marshal(target)
							check(err)
							previewBody = string(data)
						}
						w = request(t, b, op+"/preview", token, previewBody)
						if w.Code != 200 {
							t.Fatal("fresh preview denied")
						}
						check(json.Unmarshal(w.Body.Bytes(), &p))
						data, err := json.Marshal(map[string]string{"preview_id": p.ID, "confirmation": p.Confirmation})
						check(err)
						body = string(data)
					}
					w = request(t, alias, op+"/apply", token, body)
					if w.Code != 200 {
						t.Fatalf("native route alias%d denied status=%d", i, w.Code)
					}
					afterA, err := svc.Get(context.Background(), a)
					check(err)
					if !reflect.DeepEqual(unrelated, afterA) {
						t.Error("API success changed A")
					}
					var afterSecretsA string
					check(db.QueryRow("SELECT COALESCE(jsonb_agg(to_jsonb(s) ORDER BY slot)::text,'[]') FROM extension_secrets s WHERE instance_id=$1", a).Scan(&afterSecretsA))
					if secretsA != afterSecretsA {
						t.Error("API success changed A secrets")
					}
					if op == "secrets/delete" {
						var count int
						check(db.QueryRow("SELECT count(*) FROM extension_secrets WHERE instance_id=$1", b).Scan(&count))
						if count != 0 {
							t.Error("retained secrets survived")
						}
					}
					denied(b, token, body, 409)
				}
			})
		}
	}
}

// Uninstall-only route compatibility; other operation matrices remain unchanged.
func TestExtensionAPIUninstallTarget(t *testing.T) {
	db := testpg.DB(t, store.MigrateSQL)
	check := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatalf("fixture error type=%T", err)
		}
	}
	var version int
	check(db.QueryRow("SHOW server_version_num").Scan(&version))
	t.Logf("PostgreSQL=%d", version)
	random := func() string { b := make([]byte, 32); _, err := rand.Read(b); check(err); return hex.EncodeToString(b) }
	ids, err := identity.NewSQLService(context.Background(), db, "example.test")
	check(err)
	runtime := &targetAPIRuntime{}
	svc, err := extensionsadmin.NewService(db, []byte(random()[:32]), runtime)
	check(err)
	handler := (Server{Identity: ids, Authz: authz.StaticAuthorizer{}, Extensions: svc}).Handler()
	seq := 0
	for _, scope := range []string{"ops:admin:gotth-mail", "ops:admin"} {
		for _, aliasKind := range []string{"canonical", "upper", "braces", "compact", "four"} {
			seq++
			n := seq
			t.Run(scope+"/"+aliasKind, func(t *testing.T) {
				check := func(err error) {
					t.Helper()
					if err != nil {
						t.Fatalf("fixture error type=%T", err)
					}
				}
				random := func() string { b := make([]byte, 32); _, err := rand.Read(b); check(err); return hex.EncodeToString(b) }

				a := fmt.Sprintf("aaaaaaaa-aaaa-4aaa-8aaa-%012x", n*2+1)
				b := fmt.Sprintf("bbbbbbbb-bbbb-4bbb-8bbb-%012x", n*2+2)
				for i, id := range []string{a, b} {
					_, err := svc.Install(context.Background(), audit.ActorRef{Type: "local_admin", ID: "fixture"}, extensionsadmin.InstallRequest{InstanceID: id, ExtensionID: fmt.Sprintf("notification.uninstall%d-%d", n, i), Repository: "https://github.com/gotthboard/gotth-extension-target", ArtifactPin: "sha256:" + strings.Repeat("1", 64), ManifestDigest: strings.Repeat("2", 64), GrantDigest: strings.Repeat("3", 64), SessionDigest: strings.Repeat("4", 64), Metadata: extensionsadmin.Metadata{Schema: extensionsadmin.MetadataSchema}})
					check(err)
				}
				token := random()
				check(ids.AddTokenWithScopes("uninstall-api", "api_token", token, scope))
				request := func(id, action, credential, body string) *httptest.ResponseRecorder {
					req := httptest.NewRequest("POST", "/api/v1/extensions/"+id+"/uninstall/"+action, strings.NewReader(body))
					if credential != "" {
						req.Header.Set("Authorization", "Bearer "+credential)
					}
					w := httptest.NewRecorder()
					handler.ServeHTTP(w, req)
					if runtime.calls != 0 {
						t.Fatal("API runtime side effect")
					}
					if strings.Contains(w.Body.String(), token) {
						t.Fatal("credential reflected")
					}
					return w
				}
				w := request(b, "preview", token, "{}")
				if w.Code != 200 {
					t.Fatal("preview denied")
				}
				var p extensionsadmin.Preview
				check(json.Unmarshal(w.Body.Bytes(), &p))
				if p.ID == "" || p.Confirmation == "" {
					t.Fatal("preview absent")
				}
				encoded, err := json.Marshal(previewApply{PreviewID: p.ID, Confirmation: p.Confirmation})
				check(err)
				body := string(encoded)
				denied := func(id, credential, body string, status int) {
					t.Helper()
					before := apiTargetSnapshot(t, db)
					w := request(id, "apply", credential, body)
					if w.Code != status {
						t.Errorf("denial status=%d want=%d", w.Code, status)
					}
					after := apiTargetSnapshot(t, db)
					for table, rows := range before {
						if rows != after[table] {
							t.Errorf("denial changed %s", table)
						}
					}
				}
				denied(a, token, body, 409)
				denied("{"+a+"}", token, body, 409)
				denied("invalid", token, body, 409)
				denied(strings.Repeat("a", 65536), token, body, 409)
				denied(b, random(), body, 401)
				denied(b, token, body+"{}", 400)
				denied(b, token, strings.TrimSuffix(body, "}")+",\"expected_instance_id\":\""+b+"\"}", 400)
				denied(b, "", body, 401)
				bad, err := json.Marshal(previewApply{PreviewID: p.ID, Confirmation: "wrong"})
				check(err)
				denied(b, token, string(bad), 409)
				check(ids.AddTokenWithScopes("uninstall-api", "api_token", token, "ops:admin:"+b))
				denied(b, token, body, 403)
				check(ids.AddTokenWithScopes("uninstall-api", "api_token", token, scope))
				original, err := ids.AuthenticateBearer("Bearer "+token, "api_token")
				check(err)
				old := token
				token = random()
				check(ids.AddTokenWithScopes("uninstall-api", "api_token", token, scope))
				rotated, err := ids.AuthenticateBearer("Bearer "+token, "api_token")
				check(err)
				if original.ID != rotated.ID || original.Type != rotated.Type {
					t.Fatal("rotation changed actor")
				}
				denied(b, old, body, 401)
				alias := b
				switch aliasKind {
				case "upper":
					alias = strings.ToUpper(b)
				case "braces":
					alias = "{" + b + "}"
				case "compact":
					alias = strings.ReplaceAll(b, "-", "")
				case "four":
					d := strings.ReplaceAll(b, "-", "")
					var groups []string
					for i := 0; i < 32; i += 4 {
						groups = append(groups, d[i:i+4])
					}
					alias = "{" + strings.Join(groups, "-") + "}"
				}
				unrelated, err := svc.Get(context.Background(), a)
				check(err)
				w = request(alias, "apply", token, body)
				var result map[string]bool
				check(json.Unmarshal(w.Body.Bytes(), &result))
				if w.Code != 200 || !result["uninstalled"] {
					t.Fatal("correct-target uninstall response changed")
				}
				denied(b, token, body, 409)
				var remaining int
				check(db.QueryRow("SELECT count(*) FROM extension_instances WHERE instance_id=$1", b).Scan(&remaining))
				if remaining != 0 {
					t.Error("target survived")
				}
				check(db.QueryRow("SELECT count(*) FROM extension_operation_previews WHERE instance_id=$1", b).Scan(&remaining))
				if remaining != 0 {
					t.Error("preview cascade failed")
				}
				afterA, err := svc.Get(context.Background(), a)
				check(err)
				if !reflect.DeepEqual(unrelated, afterA) {
					t.Error("unrelated target changed")
				}
				check(db.QueryRow("SELECT count(*) FROM audit_events WHERE action='extension.uninstall' AND resource_id=$1", b).Scan(&remaining))
				if remaining != 1 {
					t.Error("uninstall audit not once")
				}
			})
		}
	}
}
