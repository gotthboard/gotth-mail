package httpui

import (
	"context"
	"database/sql"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	"forgejo/gotthboard/gotth-mail/internal/admin"
	"forgejo/gotthboard/gotth-mail/internal/authn"
	"forgejo/gotthboard/gotth-mail/internal/authz"
	"forgejo/gotthboard/gotth-mail/internal/extensionsadmin"
	"forgejo/gotthboard/gotth-mail/internal/identity"
	"forgejo/gotthboard/gotth-mail/internal/store"
	"forgejo/gotthboard/gotth-mail/internal/testpg"
	"golang.org/x/net/html"
)

func paginationHandler(t *testing.T, svc *extensionsadmin.Service) http.Handler {
	t.Helper()
	ids := identity.NewService("example.test")
	for _, v := range []struct{ token, scope string }{{"page-test-admin", "ops:admin"}, {"page-test-denied", "webmail:use"}} {
		if err := ids.AddTokenWithScopes(v.token, "api_token", v.token, v.scope); err != nil {
			t.Fatal(err)
		}
	}
	now := time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC)
	session := uiSessionStore{bound: authn.BoundSession{Session: authn.Session{ID: "page-session", IdentityRefID: "admin", CreatedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour), CSRFSecretHash: csrfHash("page-csrf")}, Mailbox: "admin@example.test", Roles: []authz.RoleAssignment{{Role: authz.RoleGlobalAdmin}}}}
	return HandlerWithAdminIdentitySessionsAndExtensions(admin.NewStore(), ids, authz.StaticAuthorizer{}, session, func() time.Time { return now }, svc)
}

func paginationRequest(h http.Handler, raw, bearer, hx, restore string, cookie bool) *httptest.ResponseRecorder {
	r := httptest.NewRequest("GET", "/admin/extensions", nil)
	r.URL.RawQuery = raw
	r.Header.Set("Authorization", bearer)
	r.Header.Set("HX-Request", hx)
	r.Header.Set("HX-History-Restore-Request", restore)
	if cookie {
		withIdentityCookies(r, "page-session", "page-csrf")
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func paginationToken(key string) string {
	return "v1." + base64.RawURLEncoding.EncodeToString([]byte(key))
}

func paginationFixture(t *testing.T) (*sql.DB, *extensionsadmin.Service, http.Handler) {
	t.Helper()
	// Unicode cursor/key evidence is scoped to a real UTF8 database, not a claim
	// about arbitrary schema-legal SQL_ASCII bytes or target deployment encoding.
	t.Setenv("LC_ALL", "C.UTF-8")
	db := testpg.DB(t, store.MigrateSQL)
	var encoding, collate, ctype string
	if err := db.QueryRow("SELECT pg_encoding_to_char(encoding),datcollate,datctype FROM pg_database WHERE datname=current_database()").Scan(&encoding, &collate, &ctype); err != nil {
		t.Fatal(err)
	}
	if encoding != "UTF8" {
		t.Fatal("UTF8 fixture required")
	}
	t.Logf("actual encoding=%s collate=%s ctype=%s", encoding, collate, ctype)
	rt := &inventoryNoRuntime{}
	svc, err := extensionsadmin.NewService(db, []byte(strings.Repeat("k", 32)), rt)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if rt.calls != 0 {
			t.Errorf("forbidden runtime dispatches=%d", rt.calls)
		}
	})
	_, err = db.Exec("INSERT INTO extension_instances(instance_id,product,extension_id,repository,artifact_pin,manifest_sha256,grant_sha256,session_sha256,metadata_json,lifecycle,health_code,created_at,updated_at) SELECT md5(g::text)::uuid,$1,'page.'||lpad(g::text,3,'0'),'https://github.com/gotthboard/gotth-extension-page','sha256:'||repeat('1',64),repeat('2',64),repeat('3',64),repeat('4',64),'{\"fields\":[]}'::jsonb,'stopped','extension.ready',CURRENT_TIMESTAMP,CURRENT_TIMESTAMP FROM generate_series(1,101) g", extensionsadmin.Product)
	if err != nil {
		t.Fatal(err)
	}
	return db, svc, paginationHandler(t, svc)
}

func TestInventoryPaginationAdmissionOrder(t *testing.T) {
	for _, tc := range []struct {
		name, bearer    string
		cookie, missing bool
		status          int
	}{
		{"no-auth", "", false, false, 401}, {"denied", "Bearer page-test-denied", false, false, 403},
		{"bad-bearer-before-cookie", "Bearer wrong", true, false, 401},
		{"nil-bearer", "Bearer page-test-admin", false, true, 503}, {"nil-cookie", "", true, true, 503},
	} {
		t.Run(tc.name, func(t *testing.T) {
			svc := &extensionsadmin.Service{}
			if tc.missing {
				svc = nil
			}
			h := paginationHandler(t, svc)
			w := paginationRequest(h, "after=PRIVATE%", tc.bearer, "true", "", tc.cookie)
			if w.Code != tc.status {
				t.Fatalf("status %d want%d", w.Code, tc.status)
			}
			if strings.Contains(w.Body.String(), "PRIVATE") || w.Header().Get("Cache-Control") != "private, no-store" || !strings.Contains(w.Header().Get("Vary"), "HX-History-Restore-Request") {
				t.Fatal("admission error reflection/headers")
			}
		})
	}
	h := paginationHandler(t, nil)
	for _, method := range []string{"POST", "PUT"} {
		r := httptest.NewRequest(method, "/admin/extensions?after=PRIVATE%25", nil)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != 404 {
			t.Fatal("method guard must precede auth/parse", w.Code)
		}
	}
}

func TestInventoryPaginationInputPG(t *testing.T) {
	db, _, h := paginationFixture(t)
	for _, tc := range []struct {
		raw    string
		status int
	}{{"after=", 400}, {"theme=dark&after=" + paginationToken("page.050"), 200}} {
		w := paginationRequest(h, tc.raw, "", "", "", true)
		if w.Code != tc.status {
			t.Errorf("cookie pagination status%d want%d", w.Code, tc.status)
		}
	}
	bad := []struct{ name, raw string }{
		{"empty", "after="}, {"bare", "after"}, {"duplicate", "after=" + paginationToken("page.050") + "&after=" + paginationToken("page.060")},
		{"decoded-alias", "after=" + paginationToken("page.050") + "&%61fter=" + paginationToken("page.060")},
		{"escape", "x=PRIVATE%"}, {"separator", "x=PRIVATE;value"}, {"oversized-query", "x=" + strings.Repeat("a", 4095)},
		{"version", "after=v2.YWJj"}, {"missing-version", "after=YWJj"}, {"empty-payload", "after=v1."},
		{"padded", "after=v1.YWJjeA=="}, {"noncanonical", "after=v1.YWJjeB"}, {"alphabet", "after=v1.++++"},
		{"invalid-utf8", "after=" + paginationToken(string([]byte{255, 255, 255}))}, {"nul", "after=" + paginationToken("ab\x00c")},
		{"two-runes", "after=" + paginationToken("界界")}, {"two-ascii", "after=" + paginationToken("ab")},
		{"129-runes", "after=" + paginationToken(strings.Repeat("x", 129))}, {"over512", "after=" + paginationToken(strings.Repeat("😀", 129))},
	}
	for _, tc := range bad {
		t.Run(tc.name, func(t *testing.T) {
			w := paginationRequest(h, tc.raw, "Bearer page-test-admin", "true", "", false)
			if w.Code != 400 {
				t.Errorf("status%d want400", w.Code)
			}
			if strings.Contains(w.Body.String(), "PRIVATE") || strings.Contains(w.Body.String(), "<article") || strings.Contains(w.Body.String(), inventoryMarker) {
				t.Error("invalid query reflected/partial content")
			}
		})
	}
	for _, tc := range []struct{ name, raw, theme string }{
		{"absent", "", "system"}, {"first-theme", "theme=dark&theme=light&x=PRIVATE", "dark"},
		{"unknown-theme", "theme=unknown&x=PRIVATE", "system"}, {"empty-first-theme", "theme=&theme=dark", "system"},
		{"raw4096", "x=" + strings.Repeat("a", 4094), "system"},
		{"three-runes", "after=" + paginationToken("界界界"), "system"},
		{"maximum", "after=" + paginationToken(strings.Repeat("😀", 128)), "system"},
		{"minimum", "after=" + paginationToken("abc"), "system"},
		{"punctuation", "after=" + paginationToken("quote\" back\\,{space} "), "system"},
		{"encoded-key", "%61fter=" + paginationToken("page.050") + "&theme=light", "light"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := paginationRequest(h, tc.raw, "Bearer page-test-admin", "", "", false)
			if w.Code != 200 || !strings.Contains(w.Body.String(), "data-theme=\""+tc.theme+"\"") || strings.Contains(w.Body.String(), "PRIVATE") {
				t.Fatalf("valid input/theme status%d", w.Code)
			}
		})
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	w := paginationRequest(h, "after=", "Bearer page-test-admin", "", "", false)
	if w.Code != 400 {
		t.Fatal("parse must precede SQL", w.Code)
	}
	w = paginationRequest(h, "", "Bearer page-test-admin", "true", "", false)
	if w.Code != 500 || w.Body.String() != "extension inventory unavailable\n" || strings.Contains(w.Body.String(), inventoryMarker) {
		t.Fatal("selected read error envelope", w.Code)
	}
}

type paginationHTML struct {
	ids    []string
	links  map[string]string
	themes map[string]string
	navs   int
}

func paginationDocument(t *testing.T, body string) paginationHTML {
	t.Helper()
	root, err := html.Parse(strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	out := paginationHTML{links: map[string]string{}, themes: map[string]string{}}
	walkUpdateHTML(root, func(n *html.Node) {
		if n.Data == "article" {
			out.ids = append(out.ids, updateAttr(n, "data-extension-id"))
		}
		if n.Data == "nav" && updateAttr(n, "aria-label") == "Inventory pages" {
			out.navs++
			found := false
			for p := n.Parent; p != nil; p = p.Parent {
				if updateAttr(p, "id") == "extension-inventory" {
					found = true
				}
			}
			if strings.Contains(body, "<!doctype") && !found {
				t.Error("pager outside swapped region")
			}
		}
		if n.Data == "a" {
			if id := updateAttr(n, "id"); id != "" {
				out.links[id] = updateAttr(n, "href")
			}
			if n.FirstChild != nil && strings.HasSuffix(n.FirstChild.Data, " theme") {
				out.themes[n.FirstChild.Data] = updateAttr(n, "href")
			}
			for _, attr := range n.Attr {
				if strings.HasPrefix(attr.Key, "hx-") {
					t.Error("operative HX attribute on native anchor")
				}
			}
		}
	})
	return out
}

func TestInventoryPaginationNavigationPG(t *testing.T) {
	db, svc, h := paginationFixture(t)
	svc.RuntimeBlockReason = func() string { return "read-only fixture observation" }
	before := targetUISnapshot(t, db)
	rows, err := db.Query("SELECT instance_id FROM extension_instances WHERE product=$1 ORDER BY extension_id", extensionsadmin.Product)
	if err != nil {
		t.Fatal(err)
	}
	var want []string
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			t.Fatal(err)
		}
		want = append(want, id)
	}
	if err = rows.Err(); err != nil {
		t.Fatal(err)
	}
	rows.Close()
	raw := "theme=dark"
	var seen []string
	for page := 0; page < 3; page++ {
		w := paginationRequest(h, raw, "Bearer page-test-admin", "", "", false)
		if w.Code != 200 {
			t.Fatal(w.Code)
		}
		body := w.Body.String()
		doc := paginationDocument(t, body)
		if doc.navs != 1 || !strings.Contains(body, "Up to 50 entries per page") {
			t.Error("pagination landmark/explanation")
		}
		seen = append(seen, doc.ids...)
		q, _ := url.ParseQuery(raw)
		after := q.Get("after")
		for _, id := range []string{"inventory-refresh", "inventory-reload"} {
			u, err := url.Parse(doc.links[id])
			if err != nil || u.Path != "/admin/extensions" || u.Query().Get("theme") != "dark" || u.Query().Get("after") != after {
				t.Error("refresh/reload lost current page", id)
			}
		}
		for _, theme := range []string{"system", "light", "dark"} {
			label := strings.ToUpper(theme[:1]) + theme[1:] + " theme"
			u, err := url.Parse(doc.themes[label])
			if err != nil || u.Query().Get("theme") != theme || u.Query().Get("after") != after {
				t.Error("theme lost page", theme)
			}
		}
		if page == 0 {
			if doc.links["inventory-first"] != "" {
				t.Error("first link on first page")
			}
		} else {
			u, _ := url.Parse(doc.links["inventory-first"])
			if u.Path != "/admin/extensions" || u.Query().Get("after") != "" || u.Query().Get("theme") != "dark" {
				t.Error("First URL")
			}
		}
		if page < 2 {
			u, err := url.Parse(doc.links["inventory-next"])
			if err != nil || u.Path != "/admin/extensions" || u.Query().Get("theme") != "dark" {
				t.Fatal("Next URL")
			}
			expected := paginationToken("page.050")
			if page == 1 {
				expected = paginationToken("page.100")
			}
			if u.Query().Get("after") != expected {
				t.Error("next cursor is not last selected key")
			}
			raw = u.RawQuery
		} else if doc.links["inventory-next"] != "" {
			t.Error("Next beyond end")
		}
	}
	if !reflect.DeepEqual(seen, want) {
		t.Error("native link traversal lost/duplicated/reordered rows")
	}
	for _, tc := range []struct {
		hx, restore string
		fragment    bool
	}{{"", "", false}, {"true", "", true}, {"true", "true", false}, {"true", "false", true}, {"True", "", false}, {"true, false", "", false}, {"", "true", false}} {
		w := paginationRequest(h, "theme=light&after="+paginationToken("page.050"), "Bearer page-test-admin", tc.hx, tc.restore, false)
		body := w.Body.String()
		if w.Code != 200 || strings.HasPrefix(body, inventoryMarker) != tc.fragment || strings.Count(body, "aria-label=\"Inventory pages\"") != 1 || strings.Contains(body, "<!doctype") == tc.fragment {
			t.Error("HX/history/full/marker envelope", tc)
		}
		if w.Header().Get("Cache-Control") != "private, no-store" || !strings.Contains(w.Header().Get("Vary"), "HX-Request") {
			t.Error("headers")
		}
	}
	broken := &inventoryBrokenWriter{header: make(http.Header)}
	request := httptest.NewRequest("GET", "/admin/extensions?theme=dark", nil)
	request.Header.Set("Authorization", "Bearer page-test-admin")
	h.ServeHTTP(broken, request)
	if broken.status != 200 || broken.writes != 1 {
		t.Error("route transport failure rewritten after committed200")
	}
	if !reflect.DeepEqual(before, targetUISnapshot(t, db)) {
		t.Error("paging mutated durable state")
	}
	// Current service legacy List is still all-row; no API implementation changes.
	if items, err := svc.List(context.Background()); err != nil || len(items) != 101 {
		t.Error("legacy List no longer full")
	}
	for _, n := range []string{"51", "101"} {
		if _, err := db.Exec("UPDATE extension_instances SET metadata_json='{\"fields\":\"PRIVATE\"}' WHERE instance_id=md5($1)::uuid", n); err != nil {
			t.Fatal(err)
		}
	}
	w := paginationRequest(h, "", "Bearer page-test-admin", "true", "", false)
	if w.Code != 200 || strings.Count(w.Body.String(), "<article") != 50 {
		t.Fatal("malformed sentinel/later row broke first page", w.Code)
	}
	w = paginationRequest(h, "after="+paginationToken("page.050"), "Bearer page-test-admin", "true", "", false)
	if w.Code != 500 || w.Body.String() != "extension inventory unavailable\n" {
		t.Error("selected corruption did not fail whole page")
	}
	if _, err := svc.List(context.Background()); err == nil {
		t.Error("legacy List suppressed off-page corruption")
	}
	if _, err := db.Exec("DELETE FROM extension_instances"); err != nil {
		t.Fatal(err)
	}
	for _, cursor := range []string{"", paginationToken("page.050")} {
		raw := "theme=dark"
		if cursor != "" {
			raw += "&after=" + cursor
		}
		w = paginationRequest(h, raw, "Bearer page-test-admin", "", "", false)
		doc := paginationDocument(t, w.Body.String())
		if w.Code != 200 || doc.links["inventory-next"] != "" {
			t.Error("empty page status/Next")
		}
		if cursor == "" {
			if !strings.Contains(w.Body.String(), "No extensions installed.") {
				t.Error("first empty text")
			}
		} else {
			if strings.Contains(w.Body.String(), "No extensions installed.") || !strings.Contains(w.Body.String(), "No entries after this position.") || doc.links["inventory-first"] == "" {
				t.Error("stale cursor claims global emptiness")
			}
		}
	}
}
