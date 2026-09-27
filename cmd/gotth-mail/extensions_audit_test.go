package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"forgejo/gotthboard/gotth-mail/internal/audit"
	"forgejo/gotthboard/gotth-mail/internal/authn"
	"forgejo/gotthboard/gotth-mail/internal/authz"
	"forgejo/gotthboard/gotth-mail/internal/extensionsadmin"
	"forgejo/gotthboard/gotth-mail/internal/identity"
	"forgejo/gotthboard/gotth-mail/internal/store"
	"forgejo/gotthboard/gotth-mail/internal/testpg"
	"golang.org/x/net/html"
)

// Runtime mount proof with real registry/audit SQL. Login binding injection is
// intentional here; durable session and role truth is tested in httpui.
func TestExtensionAuditBrowserRuntimeLink(t *testing.T) {
	if os.Getenv("GOTTH_AUDIT_REQUIRE_PG16") == "1" {
		for _, name := range []string{"initdb", "postgres", "createdb"} {
			_, err := exec.LookPath(name)
			acceptanceCheck(t, err)
		}
	}
	db := testpg.DB(t, store.MigrateSQL)
	var version int
	acceptanceCheck(t, db.QueryRow("SELECT current_setting('server_version_num')::int").Scan(&version))
	if os.Getenv("GOTTH_AUDIT_REQUIRE_PG16") == "1" && (version < 160000 || version >= 170000) {
		t.Fatal("PG16 required")
	}
	t.Logf("PostgreSQL=%d", version)
	server := referenceServer()
	server.AuditDB = db
	server.Identity = identity.NewService("example.test")
	bearer, csrf, sid := acceptanceRandom(t), acceptanceRandom(t), acceptanceRandom(t)
	acceptanceCheck(t, server.Identity.AddTokenWithScopes("audit-fixture", "api_token", bearer, "ops:admin"))
	now := time.Now().UTC()
	sum := sha256.Sum256([]byte(csrf))
	server.OIDCStore = acceptanceSessions{Store: authn.NewStore(), bound: authn.BoundSession{Session: authn.Session{ID: sid, IdentityRefID: acceptanceUUID(t), CreatedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour), CSRFSecretHash: base64.RawURLEncoding.EncodeToString(sum[:])}, Mailbox: "admin@example.test", Roles: []authz.RoleAssignment{{Role: authz.RoleGlobalAdmin}}}}
	svc, err := extensionsadmin.NewService(db, []byte(acceptanceRandom(t)[:32]), nil)
	acceptanceCheck(t, err)
	server.Extensions = svc
	id := acceptanceUUID(t)
	_, err = svc.Install(context.Background(), audit.ActorRef{Type: "local_admin", ID: "fixture"}, extensionsadmin.InstallRequest{InstanceID: id, ExtensionID: "notification.audit", Repository: "https://github.com/gotthboard/gotth-extension-audit", ArtifactPin: "sha256:" + acceptanceRandom(t), ManifestDigest: acceptanceRandom(t), GrantDigest: acceptanceRandom(t), SessionDigest: acceptanceRandom(t), Metadata: extensionsadmin.Metadata{Schema: extensionsadmin.MetadataSchema}})
	acceptanceCheck(t, err)
	h := runtimeMux(server)
	request := func(path, auth string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("GET", path, nil)
		r.AddCookie(&http.Cookie{Name: "gotth_mail_session", Value: sid})
		r.AddCookie(&http.Cookie{Name: "gotth_mail_csrf", Value: csrf})
		if auth != "" {
			r.Header.Set("Authorization", auth)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	detail := request("/admin/extensions/"+id, "")
	if detail.Code != 200 {
		t.Fatal("detail rejected")
	}
	root, err := html.Parse(strings.NewReader(detail.Body.String()))
	acceptanceCheck(t, err)
	href := ""
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Data == "section" {
			for _, a := range n.Attr {
				if a.Key == "id" && a.Val == "audit" {
					var links func(*html.Node)
					links = func(x *html.Node) {
						if x.Data == "a" {
							for _, a := range x.Attr {
								if a.Key == "href" {
									href = a.Val
								}
							}
						}
						for c := x.FirstChild; c != nil; c = c.NextSibling {
							links(c)
						}
					}
					links(n)
				}
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(root)
	if href == "" {
		t.Fatal("audit link missing")
	}
	followed := request(href, "")
	if followed.Code != 200 || followed.Header().Get("Content-Type") != "application/x-ndjson; charset=utf-8" || !strings.Contains(followed.Body.String(), "extension.install") {
		t.Errorf("ordinary runtime link status=%d content_type=%q; expected scoped NDJSON", followed.Code, followed.Header().Get("Content-Type"))
	}
	if href != "/admin/extensions/"+id+"/audit" || !strings.Contains(detail.Body.String(), "1,000") || !strings.Contains(detail.Body.String(), "not a complete-history export") {
		t.Error("link lacks dedicated recent-export contract")
	}
	// General API deliberately remains bearer-only, including when valid cookies exist.
	path := "/api/v1/audit/export?format=jsonl&resource_type=extension&resource_id=" + id
	if request(path, "").Code != 401 {
		t.Error("API cookie fallback introduced")
	}
	for _, format := range []string{"jsonl", "csv"} {
		res := request(strings.Replace(path, "jsonl", format, 1), "Bearer "+bearer)
		if res.Code != 200 || !strings.Contains(res.Body.String(), "extension.install") {
			t.Errorf("existing bearer %s export failed", format)
		}
	}
	r := httptest.NewRequest("POST", "/api/v1/audit/retention/preview?policy=older-than-90d", nil)
	r.AddCookie(&http.Cookie{Name: "gotth_mail_session", Value: sid})
	r.AddCookie(&http.Cookie{Name: "gotth_mail_csrf", Value: csrf})
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 401 {
		t.Error("API mutation cookie fallback introduced")
	}
	if request("/admin/extensions/"+id+"/audit", "Bearer invalid").Code != 401 {
		t.Error("dedicated audit route did not reject explicit bad bearer with 401")
	}
}
