package httpui

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"forgejo/gotthboard/gotth-mail/internal/admin"
	"forgejo/gotthboard/gotth-mail/internal/audit"
	"forgejo/gotthboard/gotth-mail/internal/authn"
	"forgejo/gotthboard/gotth-mail/internal/authz"
	"forgejo/gotthboard/gotth-mail/internal/extensionsadmin"
	"forgejo/gotthboard/gotth-mail/internal/identity"
	"forgejo/gotthboard/gotth-mail/internal/store"
	"forgejo/gotthboard/gotth-mail/internal/testpg"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestInventoryGeneratorRejectsSourceOverlap(t *testing.T) {
	script, err := os.ReadFile("../../scripts/generate-extension-inventory.sh")
	if err != nil {
		t.Fatal(err)
	}
	base := t.TempDir()
	root := filepath.Join(base, "source")
	for _, dir := range []string{filepath.Join(root, "scripts"), filepath.Join(root, "inside"), filepath.Join(base, "source-sibling"), filepath.Join(base, "cache"), filepath.Join(base, "modules"), filepath.Join(base, "temp"), filepath.Join(base, "bin")} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(root, "scripts/generate-extension-inventory.sh"), script, 0700); err != nil {
		t.Fatal(err)
	}
	events := filepath.Join(base, "events")
	// Any staging/tool/Docker attempt leaves a marker and fails; no real tool runs.
	for _, name := range []string{"jq", "bwrap", "mktemp", "docker", "go-probe", "tailwind-probe"} {
		if err := os.WriteFile(filepath.Join(base, "bin", name), []byte(`#!/bin/sh
echo effect >> "$EVENTS"
exit 91
`), 0700); err != nil {
			t.Fatal(err)
		}
	}
	for _, variable := range []string{"GOCACHE", "GOMODCACHE", "TMPDIR"} {
		for _, relation := range []string{"equal", "ancestor", "descendant", "sibling-prefix"} {
			t.Run(variable+"/"+relation, func(t *testing.T) {
				_ = os.Remove(events)
				dirs := map[string]string{"GOCACHE": filepath.Join(base, "cache"), "GOMODCACHE": filepath.Join(base, "modules"), "TMPDIR": filepath.Join(base, "temp")}
				dirs[variable] = map[string]string{"equal": root, "ancestor": base, "descendant": filepath.Join(root, "inside"), "sibling-prefix": filepath.Join(base, "source-sibling")}[relation]
				cmd := exec.Command("bash", filepath.Join(root, "scripts/generate-extension-inventory.sh"), "--check")
				cmd.Env = append(os.Environ(), "PATH="+filepath.Join(base, "bin")+":"+os.Getenv("PATH"), "EVENTS="+events, "GO_BIN="+filepath.Join(base, "bin/go-probe"), "TAILWINDCSS_BIN="+filepath.Join(base, "bin/tailwind-probe"))
				for k, v := range dirs {
					cmd.Env = append(cmd.Env, k+"="+v)
				}
				out, err := cmd.CombinedOutput()
				if relation == "sibling-prefix" {
					if err == nil || !bytes.Contains(out, []byte("unreviewed tool manifest")) {
						t.Fatalf("sibling rejected as overlap: %v %s", err, out)
					}
					if _, err := os.Stat(events); err != nil {
						t.Fatal("effect-marker equipment did not run", err)
					}
					return
				}
				if err == nil || !bytes.Contains(out, []byte("source overlap")) {
					t.Fatalf("expected source overlap denial: %v %s", err, out)
				}
				if _, err := os.Stat(events); !os.IsNotExist(err) {
					t.Fatal("tool/staging/Docker side effect")
				}
				for _, dir := range []string{filepath.Join(root, "inside"), filepath.Join(base, "cache"), filepath.Join(base, "modules"), filepath.Join(base, "temp")} {
					entries, _ := os.ReadDir(dir)
					if len(entries) != 0 {
						t.Fatal("writable directory changed", dir)
					}
				}
				actual, _ := os.ReadFile(filepath.Join(root, "scripts/generate-extension-inventory.sh"))
				if !bytes.Equal(actual, script) {
					t.Fatal("source changed")
				}
			})
		}
	}
}

func TestInventoryGeneratorContract(t *testing.T) {
	if os.Getenv("GOTTH_RENDERER_TOOL_TESTS") != "1" {
		t.Skip("explicit offline renderer tool environment required")
	}
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	goBin, twBin := os.Getenv("RENDERER_GO_BIN"), os.Getenv("TAILWINDCSS_BIN")
	if goBin == "" || twBin == "" || os.Getenv("RENDERER_GOMODCACHE") == "" {
		t.Fatal("missing required pinned test equipment")
	}
	fixture := func() string {
		dst, err := os.MkdirTemp(filepath.Dir(os.Getenv("TMPDIR")), "inventory-source-fixture-")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { os.RemoveAll(dst) })
		for _, name := range []string{"go.mod", "go.sum", "scripts/generate-extension-inventory.sh", "tools/renderer/go.mod", "tools/renderer/go.sum", "tools/renderer/tailwind-standalone.json"} {
			data, err := os.ReadFile(filepath.Join(root, name))
			if err != nil {
				t.Fatal(err)
			}
			target := filepath.Join(dst, name)
			if err = os.MkdirAll(filepath.Dir(target), 0700); err != nil {
				t.Fatal(err)
			}
			if err = os.WriteFile(target, data, 0600); err != nil {
				t.Fatal(err)
			}
		}
		for name, data := range map[string]string{
			"internal/httpui/extensions_inventory.templ":            "package httpui\n\ntempl GeneratorFixture() {\n <p class=\"grid p-4 text-ink md:grid-cols-2\">Safe fixture</p>\n}\n",
			"internal/httpui/assets/extensions-inventory.input.css": "@layer theme, base, components, utilities;\n@import \"tailwindcss/theme.css\" layer(theme);\n@import \"tailwindcss/utilities.css\" layer(utilities) source(none);\n@source \"../extensions_inventory.templ\";\n@theme inline { --color-ink: var(--text); }\n",
			"unrelated.html": "<div class=\"rotate-45\">ignored</div>",
		} {
			target := filepath.Join(dst, name)
			if err := os.MkdirAll(filepath.Dir(target), 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(target, []byte(data), 0600); err != nil {
				t.Fatal(err)
			}
		}
		return dst
	}
	run := func(root, bin, mode string) ([]byte, error) {
		cmd := exec.Command("bash", filepath.Join(root, "scripts/generate-extension-inventory.sh"), mode)
		cmd.Env = append(os.Environ(), "TAILWINDCSS_BIN="+bin, "GO_BIN="+goBin, "GOMODCACHE="+os.Getenv("RENDERER_GOMODCACHE"))
		return cmd.CombinedOutput()
	}
	a, b := fixture(), fixture()
	t.Run("missing-tool", func(t *testing.T) {
		out, err := run(a, "", "--write")
		if err == nil || !bytes.Contains(out, []byte("TAILWINDCSS_BIN")) {
			t.Fatalf("missing-tool denial: %v %s", err, out)
		}
	})
	t.Run("wrong-size", func(t *testing.T) {
		fake := filepath.Join(t.TempDir(), "fake")
		if err := os.WriteFile(fake, []byte("not executable"), 0700); err != nil {
			t.Fatal(err)
		}
		out, err := run(a, fake, "--write")
		if err == nil || !bytes.Contains(out, []byte("size")) {
			t.Fatalf("size denial: %v %s", err, out)
		}
	})
	t.Run("wrong-hash", func(t *testing.T) {
		fake := filepath.Join(t.TempDir(), "fake")
		f, err := os.OpenFile(fake, os.O_CREATE|os.O_RDWR, 0700)
		if err != nil {
			t.Fatal(err)
		}
		err = f.Truncate(111749248)
		f.Close()
		if err != nil {
			t.Fatal(err)
		}
		out, err := run(a, fake, "--write")
		if err == nil || !bytes.Contains(out, []byte("checksum")) {
			t.Fatalf("hash denial: %v %s", err, out)
		}
	})
	for _, dir := range []string{a, b} {
		out, err := run(dir, twBin, "--write")
		if err != nil || bytes.Contains(out, []byte("(!)")) {
			t.Fatalf("generate: %v %s", err, out)
		}
	}
	for _, name := range []string{"internal/httpui/extensions_inventory_templ.go", "internal/httpui/assets/inventory.css"} {
		left, err := os.ReadFile(filepath.Join(a, name))
		if err != nil {
			t.Fatal(err)
		}
		right, err := os.ReadFile(filepath.Join(b, name))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(left, right) {
			t.Fatal("nonreproducible", name)
		}
		if strings.HasSuffix(name, ".css") && (!bytes.Contains(left, []byte("var(--text)")) || bytes.Contains(left, []byte(".rotate-45")) || bytes.Contains(left, []byte("box-sizing: border-box"))) {
			t.Fatal("source/token/Preflight boundary")
		}
	}
	out, err := run(a, twBin, "--check")
	if err != nil {
		t.Fatalf("clean generation check: %v %s", err, out)
	}
	output := filepath.Join(a, "internal/httpui/assets/inventory.css")
	f, err := os.OpenFile(output, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.WriteString("/* stale */")
	f.Close()
	if err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(output)
	out, err = run(a, twBin, "--check")
	if err == nil || !bytes.Contains(out, []byte("stale")) {
		t.Fatalf("dirty generation accepted: %v %s", err, out)
	}
	after, _ := os.ReadFile(output)
	if !bytes.Equal(before, after) {
		t.Fatal("check mutated stale output")
	}
}

func TestInventoryHomeNavigation(t *testing.T) {
	w := httptest.NewRecorder()
	if err := writeInventoryComponent(w, httptest.NewRequest("GET", "/admin/extensions", nil), inventoryDocument(inventoryView{}), false); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(w.Body.String(), `href="/"`) {
		t.Fatal("legacy GOTTH Mail home breadcrumb missing")
	}
}

func TestInventoryRenderContract(t *testing.T) {
	const hostile = "<script>hostile&unsafe</script>"
	item := extensionsadmin.Instance{InstanceID: "00000000-0000-4000-8000-000000000018", ExtensionID: hostile, Repository: hostile, ArtifactPin: "sha256:" + strings.Repeat("a", 64), ManifestDigest: strings.Repeat("b", 64), GrantDigest: strings.Repeat("c", 64), Lifecycle: "stopped", HealthCode: "extension.untested", Capabilities: []string{"notification.send"}, Interfaces: []string{"notification.v1"}, SecretSlots: []string{"webhook.key"}, Configuration: map[string]any{"must-not-render": "private_config"}, SessionDigest: "private_session", Metadata: extensionsadmin.Metadata{Fields: []extensionsadmin.Field{{Label: "private_metadata"}}}}
	for _, fragment := range []bool{false, true} {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("GET", "/admin/extensions?theme=dark", nil)
		v := inventoryView{Items: []extensionsadmin.Instance{item}, Theme: "dark", BlockedReason: hostile}
		component := inventoryDocument(v)
		if fragment {
			component = inventoryRows(v)
		}
		if err := writeInventoryComponent(w, r, component, fragment); err != nil {
			t.Fatal(err)
		}
		body := w.Body.String()
		if w.Code != 200 {
			t.Fatal(w.Code)
		}
		for _, want := range []string{"&lt;script&gt;", "sha256:" + strings.Repeat("a", 64), strings.Repeat("b", 64), strings.Repeat("c", 64), "notification.send", "notification.v1", "webhook.key", "stopped", "extension.untested", "No update available", "No rollback pin", "Disabled", "/admin/extensions/" + item.InstanceID} {
			if !strings.Contains(body, want) {
				t.Errorf("missing projection %q", want)
			}
		}
		for _, forbidden := range []string{hostile, "private_config", "private_session", "private_metadata", "hx-get=", "hx-boost=", "style=", "name=\"csrf_token\""} {
			if strings.Contains(body, forbidden) {
				t.Errorf("unsafe body contains %q", forbidden)
			}
		}
		if fragment {
			if !strings.HasPrefix(body, inventoryMarker) || strings.Contains(body, "<script") || strings.Contains(body, "<html") {
				t.Fatal("fragment envelope")
			}
		} else {
			if strings.Count(body, "<script ") != 1 || strings.Contains(body, "htmx-2.0.10.min.js") || !strings.Contains(body, "src=\"/admin/extensions/assets/inventory.js\"") {
				t.Fatal("inventory companion must be the sole guarded loader")
			}
			for _, want := range []string{"data-theme=\"dark\"", "htmx-config", "/admin/extensions/assets/inventory.css", "/admin/extensions/assets/tokens.css", "Refresh inventory", "role=\"status\"", "role=\"alert\"", "hx-history=\"false\""} {
				if !strings.Contains(body, want) {
					t.Errorf("missing shell %s", want)
				}
			}
		}
	}
	item.AvailableUpdate = "sha256:update"
	item.PreviousArtifact = "sha256:prior"
	item.Enabled = true
	w := httptest.NewRecorder()
	if err := writeInventoryComponent(w, httptest.NewRequest("GET", "/admin/extensions", nil), inventoryRows(inventoryView{Items: []extensionsadmin.Instance{item}}), true); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"sha256:update", "sha256:prior", "Enabled"} {
		if !strings.Contains(w.Body.String(), want) {
			t.Fatal("missing", want)
		}
	}
	w = httptest.NewRecorder()
	if err := writeInventoryComponent(w, httptest.NewRequest("GET", "/admin/extensions", nil), inventoryRows(inventoryView{}), true); err != nil || !strings.Contains(w.Body.String(), "No extensions installed") {
		t.Fatal("empty inventory")
	}
	for _, in := range []string{"", "unknown", "<script>", "system", "light", "dark"} {
		want := in
		if in != "light" && in != "dark" {
			want = "system"
		}
		if inventoryTheme(in) != want {
			t.Fatal("theme normalization")
		}
	}
	for _, in := range []string{"../other", "https://evil.test", "javascript:alert(1)", "", "<script>"} {
		if inventoryDetailURL(in) != "/admin/extensions" {
			t.Fatal("non-UUID link admitted")
		}
	}
}

type inventoryRenderFailure struct{}

func (inventoryRenderFailure) Render(_ context.Context, w io.Writer) error {
	_, _ = io.WriteString(w, "private_partial")
	return errors.New("private render error")
}

type inventoryBrokenWriter struct {
	header         http.Header
	status, writes int
}

func (w *inventoryBrokenWriter) Header() http.Header       { return w.header }
func (w *inventoryBrokenWriter) WriteHeader(n int)         { w.status = n; w.writes++ }
func (w *inventoryBrokenWriter) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }
func TestInventoryBufferedFailures(t *testing.T) {
	r := httptest.NewRequest("GET", "/admin/extensions", nil)
	w := httptest.NewRecorder()
	if err := writeInventoryComponent(w, r, inventoryRenderFailure{}, true); err == nil || w.Code != 500 || strings.Contains(w.Body.String(), "private") || strings.Contains(w.Body.String(), inventoryMarker) {
		t.Fatal("partial rendering escaped buffer")
	}
	broken := &inventoryBrokenWriter{header: make(http.Header)}
	if err := writeInventoryComponent(broken, r, inventoryRows(inventoryView{}), true); err == nil || broken.status != 200 || broken.writes != 1 {
		t.Fatal("transport error misrepresented as precommit failure")
	}
}

func TestInventoryHTTPBoundary(t *testing.T) {
	ids := identity.NewService("example.test")
	if err := ids.AddTokenWithScopes("inventory-admin", "api_token", "inventory-fixture-token", "ops:admin"); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 9, 27, 12, 0, 0, 0, time.UTC)
	session := uiSessionStore{bound: authn.BoundSession{Session: authn.Session{ID: "inventory-session", IdentityRefID: "admin", CreatedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour), CSRFSecretHash: csrfHash("inventory-csrf")}, Mailbox: "admin@example.test", Roles: []authz.RoleAssignment{{Role: authz.RoleGlobalAdmin}}}}
	h := HandlerWithAdminIdentitySessionsAndExtensions(admin.NewStore(), ids, authz.StaticAuthorizer{}, session, func() time.Time { return now }, nil)
	for _, tc := range []struct {
		name, bearer string
		cookie       bool
		want         int
	}{{"unauthenticated", "", false, 401}, {"bearer", "Bearer inventory-fixture-token", false, 503}, {"cookie", "", true, 503}, {"bad-bearer-precedence", "Bearer invalid", true, 401}} {
		t.Run(tc.name, func(t *testing.T) {
			for _, hx := range []string{"", "true"} {
				r := httptest.NewRequest("GET", "/admin/extensions", nil)
				r.Header.Set("HX-Request", hx)
				if tc.cookie {
					withIdentityCookies(r, "inventory-session", "inventory-csrf")
				}
				r.Header.Set("Authorization", tc.bearer)
				w := httptest.NewRecorder()
				h.ServeHTTP(w, r)
				if w.Code != tc.want {
					t.Fatal(w.Code, tc.want)
				}
				if w.Header().Get("Cache-Control") != "private, no-store" || !strings.Contains(w.Header().Get("Vary"), "HX-History-Restore-Request") || w.Header().Get("X-Frame-Options") != "DENY" || !strings.Contains(w.Header().Get("Content-Security-Policy"), "form-action 'self'") {
					t.Fatal("inventory error headers")
				}
			}
		})
	}
	for _, tc := range []struct{ asset, mime string }{{"inventory.css", "text/css; charset=utf-8"}, {"tokens.css", "text/css; charset=utf-8"}, {"htmx-2.0.10.min.js", "text/javascript; charset=utf-8"}, {"inventory.js", "text/javascript; charset=utf-8"}} {
		r := httptest.NewRequest("GET", "/admin/extensions/assets/"+tc.asset, nil)
		r.Header.Set("If-None-Match", "*")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != 200 || w.Header().Get("Content-Type") != tc.mime || w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("X-Content-Type-Options") != "nosniff" {
			t.Fatal("fixed public asset", tc.asset, w.Code)
		}
		if tc.asset == "htmx-2.0.10.min.js" && fmt.Sprintf("%x", sha256.Sum256(w.Body.Bytes())) != "71ea67185bfa8c98c39d31717c6fce5d852370fcdfd129db4543774d3145c0de" {
			t.Fatal("HTMX divergence")
		}
		w = httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("POST", "/admin/extensions/assets/"+tc.asset, nil))
		if w.Code != 405 || w.Header().Get("Allow") != "GET" {
			t.Fatal("asset method")
		}
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "/admin/extensions/assets/unknown", nil))
	if w.Code != 404 {
		t.Fatal("arbitrary asset route")
	}
}

type inventoryNoRuntime struct{ calls int }

func (r *inventoryNoRuntime) Start(context.Context, extensionsadmin.Instance, map[string][]byte) error {
	r.calls++
	return errors.New("unexpected runtime")
}
func (r *inventoryNoRuntime) Probe(context.Context, extensionsadmin.Instance) (extensionsadmin.Health, error) {
	r.calls++
	return extensionsadmin.Health{}, errors.New("unexpected runtime")
}
func (r *inventoryNoRuntime) AdmitRouting(context.Context, extensionsadmin.Instance) error {
	r.calls++
	return errors.New("unexpected runtime")
}
func (r *inventoryNoRuntime) RevokeRouting(context.Context, extensionsadmin.Instance) error {
	r.calls++
	return errors.New("unexpected runtime")
}
func (r *inventoryNoRuntime) Stop(context.Context, extensionsadmin.Instance) error {
	r.calls++
	return errors.New("unexpected runtime")
}

func TestInventoryReadOnlyProjectionPG(t *testing.T) {
	if os.Getenv("GOTTH_RENDERER_REQUIRE_PG") == "1" {
		if _, err := exec.LookPath("initdb"); err != nil {
			t.Fatal(err)
		}
	}
	db := testpg.DB(t, store.MigrateSQL)
	var version int
	if err := db.QueryRow("SELECT current_setting('server_version_num')::int").Scan(&version); err != nil {
		t.Fatal(err)
	}
	if os.Getenv("GOTTH_RENDERER_REQUIRE_PG") == "1" && (version < 160000 || version >= 170000) {
		t.Fatal("PG16 required")
	}
	t.Logf("PostgreSQL=%d", version)
	runtime := &inventoryNoRuntime{}
	svc, err := extensionsadmin.NewService(db, []byte(strings.Repeat("k", 32)), runtime)
	if err != nil {
		t.Fatal(err)
	}
	id := "00000000-0000-4000-8000-000000000029"
	_, err = svc.Install(context.Background(), audit.ActorRef{Type: "local_admin", ID: "fixture"}, extensionsadmin.InstallRequest{InstanceID: id, ExtensionID: "notification.inventory", Repository: "https://github.com/gotthboard/gotth-extension-inventory", ArtifactPin: "sha256:" + strings.Repeat("1", 64), ManifestDigest: strings.Repeat("2", 64), GrantDigest: strings.Repeat("3", 64), SessionDigest: strings.Repeat("4", 64), Capabilities: []string{"notification.send"}, Interfaces: []string{"notification.v1"}, SecretSlots: []string{"inventory.key"}, Metadata: extensionsadmin.Metadata{Schema: extensionsadmin.MetadataSchema, Fields: []extensionsadmin.Field{{Name: "inventory.key", Kind: extensionsadmin.FieldSecret, Label: "Key"}}}})
	if err != nil {
		t.Fatal(err)
	}
	actor := audit.ActorRef{Type: "local_admin", ID: "fixture"}
	input := extensionsadmin.ConfigureInput{Secrets: map[string]string{"inventory.key": "fixture-secret-never-render"}}
	preview, err := svc.PreviewConfigure(context.Background(), actor, id, input)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = svc.ApplyConfigure(context.Background(), actor, preview.ID, preview.Confirmation, input); err != nil {
		t.Fatal(err)
	}
	svc.RuntimeBlockReason = func() string { return "fixture runtime quarantined" }
	ids := identity.NewService("example.test")
	if err = ids.AddTokenWithScopes("inventory-admin", "api_token", "inventory-fixture-token", "ops:admin"); err != nil {
		t.Fatal(err)
	}
	if err = ids.AddTokenWithScopes("inventory-denied", "api_token", "inventory-denied-token", "webmail:use"); err != nil {
		t.Fatal(err)
	}
	h := HandlerWithAdminIdentitySessionsAndExtensions(admin.NewStore(), ids, authz.StaticAuthorizer{}, nil, nil, svc)
	snapshot := func() string {
		var result strings.Builder
		for _, table := range []string{"extension_instances", "extension_secrets", "extension_operation_previews", "audit_events", "sessions", "identity_refs", "role_bindings"} {
			var data string
			if err := db.QueryRow("SELECT COALESCE(jsonb_agg(to_jsonb(x) ORDER BY to_jsonb(x)::text)::text,'[]') FROM " + table + " x").Scan(&data); err != nil {
				t.Fatal(err)
			}
			result.WriteString(data)
		}
		return fmt.Sprintf("%x", sha256.Sum256([]byte(result.String())))
	}
	before := snapshot()
	for _, tc := range []struct {
		hx, restore, theme string
		fragment           bool
	}{{"", "", "system", false}, {"true", "", "dark", true}, {"true", "true", "light", false}, {"true", "false", "light", true}, {"True", "", "unknown", false}, {"true, false", "", "dark", false}, {"", "true", "dark", false}} {
		r := httptest.NewRequest("GET", "/admin/extensions?theme="+tc.theme, nil)
		r.Header.Set("Authorization", "Bearer inventory-fixture-token")
		r.Header.Set("HX-Request", tc.hx)
		r.Header.Set("HX-History-Restore-Request", tc.restore)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		body := w.Body.String()
		if w.Code != 200 || strings.HasPrefix(body, inventoryMarker) != tc.fragment || w.Header().Get("Cache-Control") != "private, no-store" || w.Header().Get("Content-Type") != "text/html; charset=utf-8" {
			t.Fatalf("projection status/envelope: %+v status=%d", tc, w.Code)
		}
		for _, want := range []string{"notification.inventory", "inventory.key", "fixture runtime quarantined"} {
			if !strings.Contains(body, want) {
				t.Fatal("missing projection", want)
			}
		}
		if strings.Contains(body, "fixture-secret-never-render") || strings.Contains(body, preview.Confirmation) {
			t.Fatal("secret/confirmation leaked")
		}
		if !tc.fragment && !strings.Contains(body, "data-theme=\""+inventoryTheme(tc.theme)+"\"") {
			t.Fatal("theme missing")
		}
		for _, header := range []string{"HX-Redirect", "HX-Location", "HX-Refresh"} {
			if w.Header().Get(header) != "" {
				t.Fatal("unexpected authority header")
			}
		}
	}
	denied := httptest.NewRequest("GET", "/admin/extensions", nil)
	denied.Header.Set("Authorization", "Bearer inventory-denied-token")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, denied)
	if w.Code != 403 {
		t.Fatal("role denial", w.Code)
	}
	if before != snapshot() || runtime.calls != 0 {
		t.Fatal("GET mutated SQL or touched runtime")
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("GET", "/admin/extensions", nil)
	r.Header.Set("Authorization", "Bearer inventory-fixture-token")
	r.Header.Set("HX-Request", "true")
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 500 || w.Header().Get("Cache-Control") != "private, no-store" || !strings.Contains(w.Body.String(), "extension inventory unavailable") || strings.Contains(w.Body.String(), "sql:") {
		t.Fatal("SQL error boundary", w.Code)
	}
}

func TestInventoryCompanionContract(t *testing.T) {
	if _, err := exec.LookPath("node"); err != nil {
		if os.Getenv("GOTTH_RENDERER_REQUIRE_NODE") == "1" {
			t.Fatal(err)
		}
		t.Skip("Node test equipment unavailable")
	}
	const harness = `const fs=require('fs'),vm=require('vm'),assert=require('node:assert/strict');
const source=fs.readFileSync(process.argv[1],'utf8');
const config={allowEval:false,allowScriptTags:false,selfRequestsOnly:true,includeIndicatorStyles:false,historyEnabled:false,historyCacheSize:0,historyRestoreAsHxRequest:false,allowNestedOobSwaps:false,timeout:10000};
function fixture(option={}){
 const listeners={},timers=new Map(),nodes={};let timer=0,reloaded=0,appends=0,script;
 function element(id){const attrs={};return {id,attrs,hidden:false,textContent:'original rows',sheet:{cssRules:[{}]},rel:'stylesheet',get href(){return new URL(attrs.href,'http://fixture').href},getAttribute(n){return attrs[n]??null},setAttribute(n,v){if(n==='hx-get'){assert(listeners['htmx:beforeRequest']);assert(listeners['htmx:beforeOnLoad']);assert(listeners['htmx:beforeSwap']);}attrs[n]=String(v)},removeAttribute(n){delete attrs[n]},replaceChildren(){this.textContent=''},cloneNode(){const e=element(id);Object.assign(e.attrs,attrs);return e},replaceWith(e){nodes[id]=e}}}
 for(const id of ['inventory-refresh','inventory-reload','extension-inventory','inventory-status','inventory-error','inventory-tokens-css','inventory-utilities-css'])nodes[id]=element(id);
 nodes['inventory-refresh'].attrs.href='/admin/extensions?theme=dark';nodes['inventory-reload'].attrs.href='/admin/extensions?theme=dark';
 nodes['inventory-tokens-css'].attrs.href='/admin/extensions/assets/tokens.css';nodes['inventory-utilities-css'].attrs.href='/admin/extensions/assets/inventory.css';
 nodes['extension-inventory'].attrs['aria-busy']='false';nodes['inventory-status'].textContent='Inventory ready.';nodes['inventory-error'].textContent='';
 if(option.css)nodes[option.css].sheet=null;
 const on=(name,fn)=>{(listeners[name]??=[]).push(fn)};
 const doc={body:{addEventListener:on,getAttribute:()=>option.history?'true':'false'},readyState:'complete',getElementById:id=>nodes[id],addEventListener:on,querySelector:()=>option.meta?null:{getAttribute:()=>JSON.stringify(config)},createElement(tag){assert.equal(tag,'script');const handlers={};return {handlers,addEventListener:(n,f)=>handlers[n]=f}},head:{appendChild(s){script=s;appends++;assert.equal(doc.readyState,'complete');assert.equal(s.src,'/admin/extensions/assets/htmx-2.0.10.min.js');assert(s.handlers.load);assert(s.handlers.error);assert(listeners.pageshow);assert(listeners['htmx:beforeRequest']);if(!option.delay)completeVendor()}}};
 function completeVendor(){if(option.missing){script.handlers.error();return;}win.htmx=htmx;script.handlers.load();}
 const htmx={version:'2.0.10',config:{...config},process(){if(option.process)throw Error('injected process error')}};
 if(option.config)htmx.config[option.config]=true;if(option.version)htmx.version='wrong';
 if(option.deferred)doc.readyState='interactive';
 const win={location:{origin:'http://fixture',href:option.url||'http://fixture/admin/extensions?theme=dark',reload(){reloaded++}},addEventListener:on,setTimeout(fn,ms){const id=++timer;timers.set(id,{fn,ms});return id},clearTimeout(id){timers.delete(id)}};
 vm.runInNewContext(source,{window:win,document:doc,URL,console,setTimeout:win.setTimeout,clearTimeout:win.clearTimeout});
 function fire(name,detail={}){if(detail.xhr&&!detail.requestConfig)detail.requestConfig={elt:nodes['inventory-refresh']};const e={detail,target:detail.elt||nodes['extension-inventory'],persisted:detail.persisted,preventDefault(){this.prevented=true}};for(const fn of listeners[name]||[])fn(e);return e}
 function xhr(status=200,mime='text/html; charset=utf-8',body='<!-- gotth-mail-extension-inventory-v1 --><p>new rows</p>',headers=''){return {status,responseText:body,aborts:0,abort(){this.aborts++;fire('htmx:afterRequest',{xhr:this});fire('htmx:sendAbort',{xhr:this});},getResponseHeader(n){return n.toLowerCase()==='content-type'?mime:null},getAllResponseHeaders(){return 'Content-Type: '+mime+String.fromCharCode(13,10)+headers}}}
 function begin(x=xhr()){fire('htmx:beforeRequest',{elt:nodes['inventory-refresh'],target:nodes['extension-inventory'],xhr:x});assert.equal(nodes['extension-inventory'].attrs['aria-busy'],'true');return x}
 function flush(long=false){for(const [id,t]of [...timers])if(long||t.ms<1000){timers.delete(id);t.fn()}}
 return {nodes,fire,xhr,begin,flush,win,htmx,completeVendor,get appends(){return appends},interactive(){fire('DOMContentLoaded')},ready(){doc.readyState='complete';fire('load')},get reloads(){return reloaded}};
}
{const f=fixture({deferred:true});assert.equal(f.nodes['inventory-refresh'].getAttribute('hx-get'),null);f.interactive();assert.equal(f.appends,0);f.ready();assert.equal(f.nodes['inventory-refresh'].getAttribute('hx-get'),'/admin/extensions?theme=dark');f.ready();assert.equal(f.appends,1);}
for(const suffix of ['?', '#', '#hash','?theme=light&theme=dark','?theme=light&theme=light','?theme=','?theme','?theme=unknown','?%74heme=light','?theme=%6cight','?theme=light&','?unknown=STORAGE_CANARY','?theme=light&unknown=STORAGE_CANARY']){const f=fixture({url:'http://fixture/admin/extensions'+suffix});assert.equal(f.appends,0);assert.equal(f.nodes['inventory-refresh'].getAttribute('hx-get'),null);f.fire('pageshow',{persisted:true});assert.equal(f.reloads,1);}
for(const url of ['http://u@fixture/admin/extensions','http://fixture/admin/%65xtensions','http://fixture/other']){const f=fixture({url});assert.equal(f.appends,0);}
for(const suffix of ['', '?theme=system','?theme=light','?theme=dark']){const f=fixture({url:'http://fixture/admin/extensions'+suffix});assert.equal(f.appends,1);assert(f.nodes['inventory-refresh'].getAttribute('hx-get'));}
for(const option of [{meta:true},{history:true}])assert.equal(fixture(option).appends,0);
{const f=fixture({delay:true});assert.equal(f.appends,1);assert.equal(f.nodes['inventory-refresh'].getAttribute('hx-get'),null);f.completeVendor();assert(f.nodes['inventory-refresh'].getAttribute('hx-get'));}
{const f=fixture({delay:true});f.win.location.href+='&unknown=canary';f.completeVendor();assert.equal(f.nodes['inventory-refresh'].getAttribute('hx-get'),null);}
for(const mutate of [f=>f.win.location.href+='#changed',f=>f.htmx.config.allowEval=true,f=>f.htmx.version='wrong']){const f=fixture();mutate(f);assert(f.fire('htmx:beforeRequest',{elt:f.nodes['inventory-refresh'],target:f.nodes['extension-inventory'],xhr:f.xhr()}).prevented);}
for(const option of [{missing:true},{css:'inventory-tokens-css'},{css:'inventory-utilities-css'},{config:'allowEval'},{version:true},{process:true}]){const f=fixture(option);assert.equal(f.nodes['inventory-refresh'].getAttribute('hx-get'),null);assert.equal(f.nodes['inventory-refresh'].getAttribute('href'),'/admin/extensions?theme=dark')}
{
 const f=fixture();assert.equal(f.nodes['inventory-refresh'].getAttribute('hx-get'),'/admin/extensions?theme=dark');const x=f.begin();
 assert(!f.fire('htmx:beforeOnLoad',{xhr:x,target:f.nodes['extension-inventory']}).prevented);
 assert(!f.fire('htmx:beforeSwap',{xhr:x,target:f.nodes['extension-inventory'],shouldSwap:true}).prevented);
 f.fire('htmx:afterSwap',{xhr:x,target:f.nodes['extension-inventory']});f.fire('htmx:afterRequest',{xhr:x,successful:true});f.flush();
 assert.equal(f.nodes['extension-inventory'].attrs['aria-busy'],'false');assert.equal(f.nodes['inventory-error'].textContent,'');assert.match(f.nodes['inventory-status'].textContent,/refreshed/i);
}
for(const [status,mime,body,headers]of [[401],[403],[500],[503],[204],[302],[200,'application/json'],[200,'text/html','login page'],[200,undefined,undefined,'HX-Redirect: /login'],[200,undefined,undefined,'HX-Trigger: hostile']]){
 const f=fixture(),x=f.begin(f.xhr(status,mime,body,headers));assert(f.fire('htmx:beforeOnLoad',{xhr:x,target:f.nodes['extension-inventory']}).prevented);f.fire('htmx:afterRequest',{xhr:x,successful:true});f.flush();
 assert.equal(f.nodes['extension-inventory'].attrs['aria-busy'],'false');assert(f.nodes['inventory-error'].textContent);assert(!/refreshed/i.test(f.nodes['inventory-status'].textContent));assert.equal(f.nodes['inventory-reload'].hidden,false);
 assert.equal(f.nodes['extension-inventory'].textContent,status===401||status===403?'':'original rows');
}
for(const event of ['htmx:sendError','htmx:sendAbort','htmx:timeout','htmx:swapError','htmx:onLoadError','htmx:responseError']){const f=fixture(),x=f.begin();f.fire(event,{xhr:x,target:f.nodes['extension-inventory']});assert.equal(f.nodes['extension-inventory'].attrs['aria-busy'],'false');assert(f.nodes['inventory-error'].textContent)}
{const f=fixture(),x=f.begin();f.fire('htmx:afterRequest',{xhr:x,successful:true});f.flush();assert(f.nodes['inventory-error'].textContent);assert.equal(f.nodes['extension-inventory'].attrs['aria-busy'],'false')}
{const f=fixture();f.begin();f.flush(true);assert.equal(f.nodes['extension-inventory'].attrs['aria-busy'],'false');assert(f.nodes['inventory-error'].textContent)}
{const f=fixture(),x=f.begin();assert(f.fire('htmx:beforeRequest',{elt:f.nodes['inventory-refresh'],target:f.nodes['extension-inventory'],xhr:f.xhr()}).prevented);assert(f.fire('htmx:beforeSwap',{xhr:x,target:{id:'other'},shouldSwap:true}).prevented);assert(f.nodes['inventory-error'].textContent)}
{const f=fixture();f.fire('pageshow',{persisted:true});assert.equal(f.nodes['extension-inventory'].textContent,'');assert.equal(f.nodes['extension-inventory'].hidden,true);assert.equal(f.reloads,1)}
// The vendor overwrites detail.elt with the dispatch target on beforeSwap;
// requestConfig.elt retains the initiator. Exercise actual companion with both.
for(const [code,mime,body,headers] of [[200],[200,'text/html','bad'],[200,undefined,undefined,'HX-Redirect: /login'],[401]]){
 const f=fixture(),old=f.begin(f.xhr(code,mime,body,headers));f.flush(true);
 assert.equal(old.aborts,1,'watchdog must abort retiring request');
 for(const name of ['htmx:beforeOnLoad','htmx:beforeSwap']){const detail={xhr:old,elt:f.nodes['extension-inventory'],target:f.nodes['extension-inventory'],shouldSwap:true,requestConfig:{elt:f.nodes['inventory-refresh']}};assert(f.fire(name,detail).prevented,'late owned response must be cancelled');if(name==='htmx:beforeSwap')assert.equal(detail.shouldSwap,false);}
 assert.match(f.nodes['inventory-status'].textContent,/stale/i);
 const next=f.begin();f.fire('htmx:sendAbort',{xhr:old});
 assert(f.fire('htmx:beforeOnLoad',{xhr:old,target:f.nodes['extension-inventory']}).prevented);
 assert.equal(f.nodes['extension-inventory'].attrs['aria-busy'],'true');
 assert(!f.fire('htmx:beforeOnLoad',{xhr:next,target:f.nodes['extension-inventory']}).prevented);
 f.fire('htmx:beforeSwap',{xhr:next,elt:f.nodes['extension-inventory'],target:f.nodes['extension-inventory'],shouldSwap:true});f.fire('htmx:afterSwap',{xhr:next,target:f.nodes['extension-inventory']});assert.match(f.nodes['inventory-status'].textContent,/refreshed/i);
}
{const f=fixture(),other={id:'other'},x=f.xhr();for(const name of ['htmx:beforeOnLoad','htmx:beforeSwap'])assert(!f.fire(name,{xhr:x,elt:other,target:f.nodes['extension-inventory'],requestConfig:{elt:other},shouldSwap:true}).prevented);}
{const f=fixture(),old=f.begin();old.abort=function(){this.aborts++;f.fire('htmx:sendAbort',{xhr:this});f.begin();};f.flush(true);assert.equal(old.aborts,1);assert.equal(f.nodes['extension-inventory'].attrs['aria-busy'],'true');}
console.log('PASS companion gating, exact response/swap success, every terminal failure, source isolation and BFCache mitigation (synthetic event equipment, not browser proof)');
`
	out, err := exec.Command("node", "-e", harness, "assets/inventory.js").CombinedOutput()
	if err != nil {
		t.Fatalf("companion contracts: %v\n%s", err, out)
	}
	t.Log(string(out))
}

// Render-only cost samples. Excludes SQL/auth/network and does not claim speedup.
// MaxRSS is this test process's cumulative Linux high-water mark, not total tree RSS.
func TestInventoryRenderResourceSamples(t *testing.T) {
	if os.Getenv("GOTTH_RENDERER_RESOURCE_SAMPLES") != "1" {
		t.Skip("opt-in scoped resource samples")
	}
	for _, tc := range []struct {
		name        string
		rows, label int
	}{{"empty", 0, 32}, {"one", 1, 32}, {"typical", 20, 32}, {"large", 1000, 32}, {"long-hostile", 20, 4096}} {
		items := make([]extensionsadmin.Instance, tc.rows)
		for i := range items {
			items[i] = extensionsadmin.Instance{InstanceID: fmt.Sprintf("00000000-0000-4000-8000-%012d", i), ExtensionID: strings.Repeat("<>&", tc.label), Repository: "https://github.com/gotthboard/gotth-extension-fixture", ArtifactPin: "sha256:" + strings.Repeat("a", 64), ManifestDigest: strings.Repeat("b", 64), GrantDigest: strings.Repeat("c", 64), Lifecycle: "stopped", HealthCode: "extension.untested", Capabilities: []string{"notification.send"}, Interfaces: []string{"notification.v1"}, SecretSlots: []string{"fixture.key"}}
		}
		v := inventoryView{Items: items}
		r := httptest.NewRequest("GET", "/admin/extensions", nil)
		runtime.GC()
		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)
		samples := make([]int64, 20)
		bodyBytes := 0
		var observedHeap uint64
		for i := range samples {
			start := time.Now()
			w := httptest.NewRecorder()
			err := writeInventoryComponent(w, r, inventoryRows(v), true)
			samples[i] = time.Since(start).Nanoseconds()
			if err != nil || w.Code != 200 || bytes.Count(w.Body.Bytes(), []byte("data-extension-id=")) != tc.rows {
				t.Fatal("resource oracle incomplete")
			}
			bodyBytes = w.Body.Len()
			runtime.ReadMemStats(&after)
			if after.HeapAlloc > observedHeap {
				observedHeap = after.HeapAlloc
			}
		}
		sort.Slice(samples, func(i, j int) bool { return samples[i] < samples[j] })
		var usage syscall.Rusage
		if err := syscall.Getrusage(syscall.RUSAGE_SELF, &usage); err != nil {
			t.Fatal(err)
		}
		report := map[string]any{"case": tc.name, "rows": tc.rows, "response_bytes": bodyBytes, "samples": len(samples), "p50_ns": samples[9], "p95_ns": samples[18], "p99_sample_ns": samples[19], "allocated_bytes_per_render": (after.TotalAlloc - before.TotalAlloc) / 20, "observed_heap_bytes": observedHeap, "process_high_water_rss_kib": usage.Maxrss, "scope": "render-to-recorder; excludes SQL/auth/network; no speedup or fixed-bound claim"}
		data, err := json.Marshal(report)
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("resource %s", data)
	}
}
