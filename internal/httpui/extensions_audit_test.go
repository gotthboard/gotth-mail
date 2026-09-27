package httpui

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
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
)

type auditScopeAuthorizer struct {
	authz.StaticAuthorizer
	seen    authz.Resource
	actor   authz.Actor
	action  authz.Action
	allowID string
	fail    bool
}

func (a *auditScopeAuthorizer) Decide(_ context.Context, actor authz.Actor, action authz.Action, resource authz.Resource) (authz.Decision, error) {
	a.seen, a.actor, a.action = resource, actor, action
	if a.fail {
		return authz.Decision{}, errors.New("private authorizer detail")
	}
	return authz.Decision{Allow: resource.Type == "extension" && resource.ID == a.allowID}, nil
}

func TestExtensionAuditBrowser(t *testing.T) {
	check := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	if os.Getenv("GOTTH_AUDIT_REQUIRE_PG16") == "1" {
		for _, name := range []string{"initdb", "postgres", "createdb"} {
			_, err := exec.LookPath(name)
			check(err)
		}
	}
	db := testpg.DB(t, store.MigrateSQL)
	var version int
	check(db.QueryRow("SELECT current_setting('server_version_num')::int").Scan(&version))
	if os.Getenv("GOTTH_AUDIT_REQUIRE_PG16") == "1" && (version < 160000 || version >= 170000) {
		t.Fatal("PG16 required")
	}
	t.Logf("PostgreSQL=%d", version)
	run := func(q string, args ...any) { t.Helper(); _, err := db.Exec(q, args...); check(err) }
	now := time.Date(2026, 9, 27, 0, 10, 0, 0, time.UTC)
	uuid := func(n int) string { return fmt.Sprintf("aabbccdd-0000-4000-8000-%012d", n) }
	domain, mailbox, otherMailbox, who, otherWho, role := uuid(1), uuid(2), uuid(3), uuid(4), uuid(5), uuid(6)
	const sid = "audit-test-session"
	const csrf = "audit-test-csrf"
	// Minimal durable identity fixtures, not mocked BoundSession. Login is out of scope.
	run("INSERT INTO domains(id,name,created_at,updated_at) VALUES ($1,'example.test',$2,$2)", domain, now)
	run("INSERT INTO mailboxes(id,domain_id,local_part,created_at,updated_at) VALUES ($1,$3,'admin',$4,$4),($2,$3,'other',$4,$4)", mailbox, otherMailbox, domain, now)
	run("INSERT INTO identity_refs(id,provider,issuer,subject,mailbox_id,created_at,updated_at) VALUES ($1,'authentik','https://identity.example.test','admin',$3,$5,$5),($2,'authentik','https://identity.example.test','other',$4,$5,$5)", who, otherWho, mailbox, otherMailbox, now)
	run("INSERT INTO sessions(id,identity_ref_id,csrf_secret_hash,auth_method,created_at,expires_at,last_seen_at) VALUES ($1,$2,$3,'oidc',$4,$5,$4)", sid, who, csrfHash(csrf), now.Add(-time.Minute), now.Add(time.Hour))
	run("INSERT INTO role_bindings(id,identity_ref_id,role,created_at,updated_at) VALUES ($1,$2,'global_admin',$3,$3)", role, who, now)
	ids := identity.NewService("example.test")
	check(ids.AddTokenWithScopes("audit-bearer", "api_token", "audit-fixture-bearer", "ops:admin"))
	svc, err := extensionsadmin.NewService(db, []byte(strings.Repeat("k", 32)), &retentionRuntime{})
	check(err)
	svc.Now = func() time.Time { return now }
	a, b := uuid(10), uuid(11)
	for i, id := range []string{a, b} {
		_, err := svc.Install(context.Background(), audit.ActorRef{Type: "local_admin", ID: "fixture"}, extensionsadmin.InstallRequest{InstanceID: id, ExtensionID: fmt.Sprintf("notification.audit%d", i), Repository: "https://github.com/gotthboard/gotth-extension-audit", ArtifactPin: "sha256:" + strings.Repeat("1", 64), ManifestDigest: strings.Repeat("2", 64), GrantDigest: strings.Repeat("3", 64), SessionDigest: strings.Repeat("4", 64), SecretSlots: []string{"audit.key"}, Metadata: extensionsadmin.Metadata{Schema: extensionsadmin.MetadataSchema, Fields: []extensionsadmin.Field{{Name: "audit.key", Label: "Key", Kind: extensionsadmin.FieldSecret}}}})
		check(err)
	}
	input := extensionsadmin.ConfigureInput{Secrets: map[string]string{"audit.key": "synthetic-write-only-key"}}
	p, err := svc.PreviewConfigure(context.Background(), audit.ActorRef{Type: "local_admin", ID: "fixture"}, a, input)
	check(err)
	_, err = svc.ApplyConfigure(context.Background(), audit.ActorRef{Type: "local_admin", ID: "fixture"}, p.ID, p.Confirmation, input)
	check(err)
	sessions := authn.SQLStore{DB: db}
	handler := func(service *extensionsadmin.Service, az authz.Authorizer, s authn.IdentitySessionStore) http.Handler {
		return HandlerWithAdminIdentitySessionsAndExtensions(admin.NewStore(), ids, az, s, func() time.Time { return now }, service)
	}
	h := handler(svc, authz.StaticAuthorizer{}, sessions)
	path := "/admin/extensions/" + a + "/audit"
	req := func(method, url, session, csrfCookie, authorization string) *http.Request {
		r := httptest.NewRequest(method, url, nil)
		if session != "" {
			r.AddCookie(&http.Cookie{Name: "gotth_mail_session", Value: session})
		}
		if csrfCookie != "" {
			r.AddCookie(&http.Cookie{Name: "gotth_mail_csrf", Value: csrfCookie})
		}
		if authorization != "" {
			r.Header.Set("Authorization", authorization)
		}
		return r
	}
	serve := func(h http.Handler, r *http.Request) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	get := func(url string) *httptest.ResponseRecorder { return serve(h, req("GET", url, sid, csrf, "")) }
	headers := func(t *testing.T, w *httptest.ResponseRecorder, status int) {
		t.Helper()
		if w.Code != status {
			t.Errorf("status=%d want=%d", w.Code, status)
		}
		if w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("X-Content-Type-Options") != "nosniff" {
			t.Error("cache/sniff policy missing")
		}
		if status != 200 && (w.Header().Get("Content-Disposition") != "" || strings.Contains(w.Body.String(), "private") || strings.Contains(w.Body.String(), "pq:") || strings.Contains(w.Body.String(), "synthetic-write-only")) {
			t.Error("error leaked details or attachment")
		}
	}
	snapshot := func() []string {
		var out []string
		for _, table := range []string{"extension_instances", "extension_secrets", "extension_operation_previews", "sessions", "identity_refs", "role_bindings", "audit_events"} {
			var s string
			check(db.QueryRow("SELECT COALESCE(jsonb_agg(to_jsonb(x) ORDER BY to_jsonb(x)::text)::text,'[]') FROM " + table + " x").Scan(&s))
			out = append(out, s)
		}
		return out
	}
	t.Run("durable-authentication", func(t *testing.T) {
		for _, tc := range []struct {
			name, session, cookie, authorization string
			want                                 int
		}{
			{"global-admin", sid, csrf, "", 200}, {"no-cookie", "", "", "", 401}, {"unknown-session", "unknown", csrf, "", 401}, {"missing-pair", sid, "", "", 401}, {"wrong-pair", sid, "wrong", "", 401}, {"bad-bearer", sid, csrf, "Bearer invalid", 401}, {"explicit-bearer", "", "", "Bearer audit-fixture-bearer", 200},
		} {
			t.Run(tc.name, func(t *testing.T) {
				before := snapshot()
				w := serve(h, req("GET", path, tc.session, tc.cookie, tc.authorization))
				headers(t, w, tc.want)
				if !reflect.DeepEqual(before, snapshot()) {
					t.Error("GET mutated durable state")
				}
			})
		}
		for _, tc := range []struct {
			name, change, restore string
			want                  int
		}{
			{"revoked", "UPDATE sessions SET revoked_at=created_at", "UPDATE sessions SET revoked_at=NULL", 401},
			{"expired", "UPDATE sessions SET expires_at=created_at", "UPDATE sessions SET expires_at=created_at+interval '2 hours'", 401},
			{"future-session", "UPDATE sessions SET created_at=expires_at", "UPDATE sessions SET created_at=last_seen_at", 401},
			{"disabled-mailbox", "UPDATE mailboxes SET enabled=false", "UPDATE mailboxes SET enabled=true", 401},
			{"role-removal", "DELETE FROM role_bindings", "INSERT INTO role_bindings(id,identity_ref_id,role,created_at,updated_at) VALUES ('" + role + "','" + who + "','global_admin',CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)", 403},
			{"domain-manager", "UPDATE role_bindings SET role='domain_manager',domain_id='" + domain + "'", "UPDATE role_bindings SET role='global_admin',domain_id=NULL", 403},
			{"scoped-domain", "UPDATE role_bindings SET role='scoped_domain_access',domain_id='" + domain + "'", "UPDATE role_bindings SET role='global_admin',domain_id=NULL", 403},
			{"other-identity-role", "UPDATE role_bindings SET identity_ref_id='" + otherWho + "'", "UPDATE role_bindings SET identity_ref_id='" + who + "'", 403},
		} {
			t.Run(tc.name, func(t *testing.T) {
				run(tc.change)
				defer run(tc.restore)
				before := snapshot()
				headers(t, get(path), tc.want)
				if !reflect.DeepEqual(before, snapshot()) {
					t.Error("denied GET mutated state")
				}
			})
		}
		// A real second session's CSRF value cannot authorize the first session.
		run("INSERT INTO sessions SELECT 'second',identity_ref_id,$1,auth_method,created_at,expires_at,last_seen_at,revoked_at FROM sessions WHERE id=$2", csrfHash("second-csrf"), sid)
		headers(t, serve(h, req("GET", path, sid, "second-csrf", "")), 401)
	})
	t.Run("resource-authority-and-order", func(t *testing.T) {
		az := &auditScopeAuthorizer{allowID: a}
		custom := handler(svc, az, sessions)
		headers(t, serve(custom, req("GET", "/admin/extensions/"+strings.ToUpper(a)+"/audit", sid, csrf, "")), 200)
		if az.seen != (authz.Resource{Type: "extension", ID: a}) || az.action != "ops:admin" || az.actor.ID != who || az.actor.Mailbox != "admin@example.test" || len(az.actor.Roles) != 1 {
			t.Error("wrong durable actor/resource projection")
		}
		headers(t, serve(custom, req("GET", "/admin/extensions/"+b+"/audit", sid, csrf, "")), 403)
		closed, err := sql.Open("postgres", "")
		check(err)
		check(closed.Close())
		az.fail = true
		headers(t, serve(handler(&extensionsadmin.Service{DB: closed}, az, sessions), req("GET", path, sid, csrf, "")), 403)
		headers(t, serve(handler(&extensionsadmin.Service{DB: closed}, authz.StaticAuthorizer{}, sessions), req("GET", path, "", "", "")), 401)
	})
	t.Run("protocol", func(t *testing.T) {
		for _, method := range []string{"HEAD", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"} {
			w := serve(h, req(method, path, sid, csrf, ""))
			headers(t, w, 405)
			if w.Header().Get("Allow") != "GET" {
				t.Error("GET-only Allow missing")
			}
		}
		for _, query := range []string{"format=csv", "resource_id=" + b, "resource_type=ops", "limit=1", "product=board", "x=1&x=2", "%6cimit=1001", "bad=%zz"} {
			headers(t, get(path+"?"+query), 400)
		}
		headers(t, serve(h, req("GET", path+"?limit=1", "", "", "")), 401)
		for _, id := range []string{"bad", strings.ReplaceAll(a, "-", ""), "aabbccdd-0000-4000-8000-00000000000z", a[:35], a + "0", "a%2fb"} {
			w := get("/admin/extensions/" + id + "/audit")
			if w.Code != 404 {
				t.Logf("malformed id=%q status=%d body=%q", id, w.Code, w.Body.String())
			}
			headers(t, w, 404)
		}
		// Go single-segment wildcards exclude a decoded slash-only segment.
		// This falls through to the unchanged detail prefix, not the audit handler.
		if w := get("/admin/extensions/%2f/audit"); w.Code != 400 || strings.TrimSpace(w.Body.String()) != "extension operation failed" {
			t.Error("existing slash-only prefix rejection changed")
		}
		if get(path+"/extra").Code != 404 || get(path+"/").Code != 404 {
			t.Error("extra suffix accepted")
		}
		r := req("GET", path, sid, csrf, "")
		r.Header.Set("If-None-Match", "*")
		r.Header.Set("If-Modified-Since", now.Add(time.Hour).Format(http.TimeFormat))
		w := serve(h, r)
		headers(t, w, 200)
		r = req("GET", path, "", "", "")
		r.Header.Set("If-None-Match", "*")
		headers(t, serve(h, r), 401)
		if w.Header().Get("ETag") != "" || w.Header().Get("Last-Modified") != "" {
			t.Error("protected export cache validators added")
		}
	})
	t.Run("selection-redaction-and-boundary", func(t *testing.T) {
		for _, count := range []int{0, 999, 1000, 1001, 1200} {
			t.Run(fmt.Sprint(count), func(t *testing.T) {
				run("DELETE FROM audit_events")
				// Direct legacy rows bypass write-time redaction. All selected timestamps tie
				// so id DESC has an independent arithmetic oracle; newer unrelated rows must
				// be filtered BEFORE LIMIT. Separate timestamp-first check follows below.
				run(`INSERT INTO audit_events(id,timestamp,actor_type,actor_id,action,resource_type,resource_id,before_redacted_json,after_redacted_json,correlation_id,result)
SELECT ('00000000-0000-4000-8000-'||lpad(n::text,12,'0'))::uuid,$1,'fixture','actor','selected','extension',$2,'{"nested":[{"password":"legacy-password","token":"legacy-token"}]}','{"child":{"private_key":"legacy-key","safe":"<script>text</script>"}}','audit-browser','success' FROM generate_series(1,$3) n`, now, a, count)
				run(`INSERT INTO audit_events(id,timestamp,actor_type,actor_id,action,resource_type,resource_id,before_redacted_json,after_redacted_json,correlation_id,result)
SELECT ('00000000-0000-4000-8001-'||lpad(n::text,12,'0'))::uuid,$1,'fixture','other','must-not-export',CASE WHEN n%2=0 THEN 'extension' ELSE 'ops' END,CASE WHEN n%2=0 THEN $2 ELSE $3 END,'{}','{}','other','success' FROM generate_series(1,1201) n`, now.Add(time.Hour), b, a)
				before := snapshot()
				w := get(path)
				headers(t, w, 200)
				if w.Header().Get("Content-Type") != "application/x-ndjson; charset=utf-8" || w.Header().Get("Content-Disposition") != `attachment; filename="extension-audit.jsonl"` {
					t.Error("download representation incorrect")
				}
				if strings.Contains(w.Body.String(), "legacy-") || strings.Contains(w.Body.String(), "must-not-export") {
					t.Error("legacy secret or unrelated event leaked")
				}
				raw := w.Body.String()
				got := []audit.Event{}
				if raw != "" {
					if !strings.HasSuffix(raw, "\n") {
						t.Error("missing JSONL newline")
					}
					for _, line := range strings.Split(strings.TrimSuffix(raw, "\n"), "\n") {
						var event audit.Event
						if err := json.Unmarshal([]byte(line), &event); err != nil {
							t.Fatal("invalid JSONL")
						}
						got = append(got, event)
					}
				}
				want := count
				if want > 1000 {
					want = 1000
				}
				if len(got) != want {
					t.Errorf("events=%d want=%d", len(got), want)
				}
				for i, e := range got {
					expected := fmt.Sprintf("00000000-0000-4000-8000-%012d", count-i)
					if e.ID != expected || e.Resource.ID != a || e.Resource.Type != "extension" || e.Action != "selected" || e.Actor.ID != "actor" || e.Result != "success" {
						t.Error("selection/order changed")
						break
					}
					encoded, _ := json.Marshal(e)
					if !strings.Contains(string(encoded), "[REDACTED]") {
						t.Error("nested reader redaction absent")
						break
					}
				}
				if !reflect.DeepEqual(before, snapshot()) {
					t.Error("GET changed SQL state")
				}
				if count == 1200 {
					other := get("/admin/extensions/" + b + "/audit")
					headers(t, other, 200)
					dec := json.NewDecoder(other.Body)
					seen := 0
					for dec.More() {
						var event audit.Event
						if err := dec.Decode(&event); err != nil {
							t.Fatal("invalid B JSONL")
						}
						if event.Resource.ID != b || event.Resource.Type != "extension" {
							t.Error("B export crossed resource scope")
						}
						seen++
					}
					if seen != 600 {
						t.Errorf("B events=%d want600", seen)
					}
				}
				again := get(path)
				if again.Code != w.Code || again.Body.String() != raw {
					t.Error("repeat changed result")
				}
			})
		}
		run("DELETE FROM audit_events")
		for i, stamp := range []time.Time{now.Add(time.Second), now, now.Add(time.Second)} {
			run("INSERT INTO audit_events(id,timestamp,actor_type,actor_id,action,resource_type,resource_id,before_redacted_json,after_redacted_json,correlation_id,result) VALUES ($1,$2,'fixture','actor','ordered','extension',$3,'{}','{}','order','success')", uuid(30+i), stamp, a)
		}
		w := get(path)
		var got []string
		dec := json.NewDecoder(w.Body)
		for dec.More() {
			var e audit.Event
			check(dec.Decode(&e))
			got = append(got, e.ID)
		}
		want := []string{uuid(32), uuid(30), uuid(31)}
		if !reflect.DeepEqual(got, want) {
			t.Error("timestamp then id ordering changed")
		}
	})
	t.Run("existence-and-errors", func(t *testing.T) {
		run("INSERT INTO audit_events(id,timestamp,actor_type,actor_id,action,resource_type,resource_id,before_redacted_json,after_redacted_json,correlation_id,result) VALUES ($1,$2,'fixture','actor','historic','extension',$3,'{}','{}','history','success')", uuid(98), now, uuid(99))
		headers(t, get("/admin/extensions/"+uuid(99)+"/audit"), 404)
		headers(t, serve(handler(svc, authz.StaticAuthorizer{}, nil), req("GET", path, sid, csrf, "")), 401)
		for _, service := range []*extensionsadmin.Service{nil, {}} {
			headers(t, serve(handler(service, authz.StaticAuthorizer{}, sessions), req("GET", path, sid, csrf, "")), 503)
		}
		for _, table := range []string{"extension_instances", "extension_secrets", "audit_events"} {
			t.Run(table, func(t *testing.T) {
				run("ALTER TABLE " + table + " RENAME TO private_unavailable")
				defer run("ALTER TABLE private_unavailable RENAME TO " + table)
				w := get(path)
				headers(t, w, 500)
				if strings.TrimSpace(w.Body.String()) != "extension audit unavailable" {
					t.Error("SQL error not sanitized")
				}
			})
		}
		closed, err := sql.Open("postgres", "")
		check(err)
		check(closed.Close())
		headers(t, serve(handler(svc, authz.StaticAuthorizer{}, authn.SQLStore{DB: closed}), req("GET", path, sid, csrf, "")), 401)
		run("DELETE FROM extension_instances WHERE instance_id=$1", b)
		headers(t, get("/admin/extensions/"+b+"/audit"), 404)
	})
}
