package httpui

import (
	"context"
	"errors"
	"forgejo/gotthboard/gotth-mail/internal/admin"
	"forgejo/gotthboard/gotth-mail/internal/audit"
	"forgejo/gotthboard/gotth-mail/internal/authz"
	"forgejo/gotthboard/gotth-mail/internal/extensionsadmin"
	"forgejo/gotthboard/gotth-mail/internal/identity"
	"forgejo/gotthboard/gotth-mail/internal/store"
	"forgejo/gotthboard/gotth-mail/internal/testpg"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/a-h/templ"
)

type detailResponseProbe struct {
	header   http.Header
	statuses []int
	writes   int
	body     strings.Builder
	short    bool
	failure  error
}

func (w *detailResponseProbe) Header() http.Header    { return w.header }
func (w *detailResponseProbe) WriteHeader(status int) { w.statuses = append(w.statuses, status) }
func (w *detailResponseProbe) Write(p []byte) (int, error) {
	w.writes++
	if w.failure != nil {
		return 0, w.failure
	}
	if w.short {
		w.body.Write(p[:len(p)/2])
		return len(p) / 2, nil
	}
	return w.body.Write(p)
}
func TestExtensionDetailWriter(t *testing.T) {
	for _, kind := range []string{"success", "render-failure", "cancelled-before", "cancelled-during", "short-write", "write-error", "empty"} {
		t.Run(kind, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if kind == "cancelled-before" {
				cancel()
			}
			r := httptest.NewRequest(http.MethodPost, "/admin/extensions/target", nil).WithContext(ctx)
			w := &detailResponseProbe{header: make(http.Header), short: kind == "short-write"}
			if kind == "write-error" {
				w.failure = errors.New("SECRET-transport")
			}
			calls := 0
			c := templ.ComponentFunc(func(got context.Context, out io.Writer) error {
				calls++
				if got != ctx {
					t.Error("wrong render context")
				}
				if kind == "empty" {
					return nil
				}
				if kind == "render-failure" {
					_, _ = io.WriteString(out, "SECRET-partial")
					return errors.New("SECRET-render")
				}
				if kind == "cancelled-during" {
					cancel()
				}
				_, err := io.WriteString(out, "<h1>Receipt</h1>")
				return err
			})
			err := writeExtensionDetailComponent(w, r, c)
			failedRender := kind == "render-failure" || kind == "cancelled-before" || kind == "cancelled-during"
			wantStatus := http.StatusOK
			if failedRender {
				wantStatus = http.StatusInternalServerError
			}
			if len(w.statuses) != 1 || w.statuses[0] != wantStatus {
				t.Fatalf("statuses=%v", w.statuses)
			}
			wantErr := failedRender || kind == "short-write" || kind == "write-error"
			if (err != nil) != wantErr {
				t.Fatalf("error presence mismatch")
			}
			if err != nil && strings.Contains(err.Error(), "SECRET") {
				t.Error("unsanitized error")
			}
			if strings.Contains(w.body.String(), "SECRET") {
				t.Error("partial/error leaked")
			}
			if failedRender && (!strings.Contains(w.body.String(), "verify current state") || strings.Contains(w.body.String(), "<h1>")) {
				t.Error("unsafe failure receipt")
			}
			if kind == "success" && w.body.String() != "<h1>Receipt</h1>" {
				t.Error("wrong success body")
			}
			wantCalls := 1
			if kind == "cancelled-before" {
				wantCalls = 0
			}
			if calls != wantCalls {
				t.Error("render repeated or cancelled work entered")
			}
			if w.writes > 1 {
				t.Error("transport retried")
			}
			if w.header.Get("Cache-Control") != "private, no-store" || w.header.Get("X-Content-Type-Options") != "nosniff" || w.header.Get("Referrer-Policy") != "no-referrer" || w.header.Get("X-Frame-Options") != "DENY" {
				t.Error("missing privacy headers")
			}
			if w.header.Get("Content-Security-Policy") != "default-src 'none'; script-src 'none'; style-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'; object-src 'none'" {
				t.Error("wrong CSP")
			}
			if !failedRender && w.header.Get("Content-Type") != "text/html; charset=utf-8" {
				t.Error("wrong HTML type")
			}
		})
	}
}

func TestExtensionTerminalDocument(t *testing.T) {
	for _, theme := range []string{"system", "light", "dark", "invalid\" onclick=\"bad"} {
		t.Run(theme, func(t *testing.T) {
			var out strings.Builder
			if err := extensionTerminalDocument(theme, "<script>CANARY</script>").Render(context.Background(), &out); err != nil {
				t.Fatal(err)
			}
			body := out.String()
			for _, want := range []string{"<!doctype html>", "lang=\"en\"", "name=\"viewport\"", "<h1", "Extension uninstalled", "role=\"status\"", "/admin/extensions?theme=", "/admin/extensions/assets/tokens.css", "/admin/extensions/assets/detail.css", "&lt;script&gt;CANARY&lt;/script&gt;"} {
				if !strings.Contains(strings.ToLower(body), strings.ToLower(want)) {
					t.Errorf("missing terminal semantic %q", want)
				}
			}
			for _, bad := range []string{"<script", "<form", "csrf", "preview_id", "No extensions installed", "onclick=", "htmx", "inventory.js", "style="} {
				if strings.Contains(body, bad) {
					t.Errorf("forbidden terminal content %q", bad)
				}
			}
			if !strings.Contains(body, "data-theme=\""+inventoryTheme(theme)+"\"") {
				t.Error("theme not normalized")
			}
		})
	}
	var out strings.Builder
	if err := extensionTerminalDocument("system", "").Render(context.Background(), &out); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), "Runtime blocked:") {
		t.Error("spurious blocker")
	}
}

func TestExtensionDetailAsset(t *testing.T) {
	mux := http.NewServeMux()
	registerExtensionUI(mux, nil, nil, nil, nil, nil)
	for _, method := range []string{http.MethodGet, http.MethodHead, http.MethodPost, http.MethodOptions} {
		r := httptest.NewRequest(method, "/admin/extensions/assets/detail.css", nil)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		want := http.StatusMethodNotAllowed
		if method == http.MethodGet {
			want = http.StatusOK
		}
		if w.Code != want {
			t.Fatalf("%s asset status=%d", method, w.Code)
		}
		if w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("X-Content-Type-Options") != "nosniff" {
			t.Error("asset headers")
		}
		if method == http.MethodGet {
			if w.Header().Get("Content-Type") != "text/css; charset=utf-8" || !strings.Contains(w.Body.String(), "var(--text)") {
				t.Error("not generated detail CSS")
			}
		} else if w.Header().Get("Allow") != "GET" {
			t.Error("wrong allowed method")
		}
	}
}

func TestExtensionUninstallTerminalReceipt(t *testing.T) {
	db := testpg.DB(t, store.MigrateSQL)
	runtime := &targetUIRuntime{}
	svc, err := extensionsadmin.NewService(db, []byte("0123456789abcdef0123456789abcdef"), runtime)
	if err != nil {
		t.Fatal(err)
	}
	ids, err := identity.NewSQLService(context.Background(), db, "example.test")
	if err != nil {
		t.Fatal(err)
	}
	const token = "D1-private-token-canary"
	if err := ids.AddTokenWithScopes("d1-admin", "api_token", token, "ops:admin"); err != nil {
		t.Fatal(err)
	}
	const a = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	const b = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
	actor := audit.ActorRef{Type: "local_admin", ID: "fixture"}
	for i, id := range []string{a, b} {
		name := []string{"notification.deleted", "notification.survivor"}[i]
		_, err := svc.Install(context.Background(), actor, extensionsadmin.InstallRequest{InstanceID: id, ExtensionID: name, Repository: "https://github.com/gotthboard/gotth-extension-target", ArtifactPin: "sha256:" + strings.Repeat("1", 64), ManifestDigest: strings.Repeat("2", 64), GrantDigest: strings.Repeat("3", 64), SessionDigest: strings.Repeat("4", 64), SecretSlots: []string{"private.key"}, Metadata: extensionsadmin.Metadata{Schema: extensionsadmin.MetadataSchema, Fields: []extensionsadmin.Field{{Name: "private.key", Label: "Private", Kind: extensionsadmin.FieldSecret}}}})
		if err != nil {
			t.Fatal("install fixture", err)
		}
	}
	const secret = "D1-retained-secret-canary"
	input := extensionsadmin.ConfigureInput{Secrets: map[string]string{"private.key": secret}}
	preview, err := svc.PreviewConfigure(context.Background(), actor, b, input)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.ApplyConfigure(context.Background(), actor, b, preview.ID, preview.Confirmation, input); err != nil {
		t.Fatal(err)
	}
	// Extra target preview must cascade; survivor preview must remain exactly intact.
	if _, err := svc.PreviewUninstall(context.Background(), actor, a); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.PreviewUninstall(context.Background(), actor, b); err != nil {
		t.Fatal(err)
	}
	survivor := func() string {
		var state string
		if err := db.QueryRow("SELECT jsonb_build_array((SELECT to_jsonb(i) FROM extension_instances i WHERE instance_id=$1),(SELECT jsonb_agg(to_jsonb(s) ORDER BY slot) FROM extension_secrets s WHERE instance_id=$1),(SELECT jsonb_agg(to_jsonb(p) ORDER BY id) FROM extension_operation_previews p WHERE instance_id=$1))::text", b).Scan(&state); err != nil {
			t.Fatal("survivor snapshot", err)
		}
		return state
	}
	before := survivor()
	h := HandlerWithAdminIdentitySessionsAndExtensions(admin.NewStore(), ids, authz.StaticAuthorizer{}, nil, nil, svc)
	req := func(method, path string, form url.Values) *httptest.ResponseRecorder {
		r := formReq(method, path, form, "Bearer "+token)
		r.Header.Set("HX-Request", "true")
		r.Header.Set("HX-History-Restore-Request", "true")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		for _, bad := range []string{token, secret} {
			if strings.Contains(w.Body.String(), bad) {
				t.Fatal("private value reflected")
			}
		}
		return w
	}
	path := "/admin/extensions/" + a + "?theme=dark&unrelated=QUERY-CANARY"
	old := req("GET", path, nil)
	if old.Code != 200 || !strings.Contains(old.Body.String(), "<style>") || old.Header().Get("Content-Security-Policy") != "" {
		t.Fatal("legacy GET changed")
	}
	pr := req("POST", path, url.Values{"action": {"uninstall-preview"}})
	if pr.Code != 200 || pr.Header().Get("Content-Security-Policy") != "" {
		t.Fatal("preview not legacy")
	}
	form, confirmation := configurationActionForm(t, pr.Body.String(), "uninstall-apply")
	form.Set("confirmation", "wrong")
	denied := req("POST", path, form)
	if denied.Code != 200 || denied.Header().Get("Content-Security-Policy") != "" || strings.Contains(denied.Body.String(), ">Extension uninstalled</h1>") {
		t.Fatal("denial selected terminal")
	}
	form.Set("confirmation", confirmation)
	done := req("POST", path, form)
	var instances, previews, audits int
	for _, q := range []struct {
		sql  string
		dest *int
	}{{"SELECT count(*) FROM extension_instances WHERE instance_id=$1", &instances}, {"SELECT count(*) FROM extension_operation_previews WHERE instance_id=$1", &previews}, {"SELECT count(*) FROM audit_events WHERE action='extension.uninstall' AND resource_id=$1", &audits}} {
		if err := db.QueryRow(q.sql, a).Scan(q.dest); err != nil {
			t.Fatal("durable receipt oracle", err)
		}
	}
	if instances != 0 || previews != 0 || audits != 1 || survivor() != before || runtime.calls != 0 {
		t.Fatal("incorrect uninstall/survivor/audit/cascade/runtime effects")
	}
	if req("GET", "/admin/extensions/"+a, nil).Code != 404 {
		t.Fatal("deleted detail not404")
	}
	if done.Code != 200 || !strings.Contains(done.Body.String(), ">Extension uninstalled</h1>") {
		t.Fatal("honest terminal receipt missing")
	}
	if done.Header().Get("Location") != "" || done.Header().Get("Content-Security-Policy") == "" || !strings.Contains(done.Body.String(), "data-theme=\"dark\"") {
		t.Fatal("terminal response boundary")
	}
	for _, bad := range []string{"No extensions installed", "<form", "<script", "csrf", "preview_id", confirmation, form.Get("preview_id"), "QUERY-CANARY", a, "hx-"} {
		if bad != "" && strings.Contains(done.Body.String(), bad) {
			t.Fatal("terminal contains forbidden state or authority")
		}
	}
	if !strings.Contains(done.Body.String(), "href=\"/admin/extensions?theme=dark\"") {
		t.Fatal("inventory return link")
	}
	if req("POST", path, form).Code != 404 {
		t.Fatal("replay resurrected deleted target")
	}
	if survivor() != before || runtime.calls != 0 {
		t.Fatal("post-replay survivor/runtime changed")
	}
}
