package rolebinding

import (
	"bufio"
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"forgejo/gotthboard/gotth-mail/internal/authn"
	"forgejo/gotthboard/gotth-mail/internal/identity"
	"forgejo/gotthboard/gotth-mail/internal/identityruntime"
	"forgejo/gotthboard/gotth-mail/internal/scimstore"
	gotthscim "github.com/gotthboard/gotth-scim/pkg/scim"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type bOIDC struct {
	server                 *httptest.Server
	issuer, ca, secretFile string
	mu                     sync.Mutex
	nonce, challenge       string
	exchanges              int
}

func bProvider(t *testing.T, dir string) *bOIDC {
	t.Helper()
	key, e := rsa.GenerateKey(rand.Reader, 2048)
	if e != nil {
		t.Fatal(e)
	}
	p := &bOIDC{}
	enc := base64.RawURLEncoding.EncodeToString
	p.server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/application/o/gotth-mail/.well-known/openid-configuration":
			_ = json.NewEncoder(w).Encode(map[string]any{"issuer": p.issuer, "authorization_endpoint": p.server.URL + "/authorize", "token_endpoint": p.server.URL + "/token", "jwks_uri": p.server.URL + "/jwks", "response_types_supported": []string{"code"}, "subject_types_supported": []string{"public"}, "id_token_signing_alg_values_supported": []string{"RS256"}, "token_endpoint_auth_methods_supported": []string{"client_secret_basic"}, "code_challenge_methods_supported": []string{"S256"}})
		case "/jwks":
			_ = json.NewEncoder(w).Encode(map[string]any{"keys": []any{map[string]any{"kty": "RSA", "use": "sig", "alg": "RS256", "kid": "owned-key", "n": enc(key.N.Bytes()), "e": enc(big.NewInt(int64(key.E)).Bytes())}}})
		case "/token":
			_ = r.ParseForm()
			user, pass, ok := r.BasicAuth()
			p.mu.Lock()
			defer p.mu.Unlock()
			verifier := sha256.Sum256([]byte(r.Form.Get("code_verifier")))
			if !ok || user != "gotth-mail" || pass != "owned-synthetic-client-secret" || r.Form.Get("code") != "owned-code" || enc(verifier[:]) != p.challenge || p.nonce == "" {
				http.Error(w, "owned provider authentication failed", 401)
				return
			}
			header, _ := json.Marshal(map[string]any{"alg": "RS256", "kid": "owned-key", "typ": "JWT"})
			claims, _ := json.Marshal(map[string]any{"iss": p.issuer, "sub": testSubject, "aud": "gotth-mail", "iat": time.Now().Unix(), "exp": time.Now().Add(time.Minute).Unix(), "nonce": p.nonce, "email": testMailbox, "email_verified": true})
			unsigned := enc(header) + "." + enc(claims)
			h := sha256.Sum256([]byte(unsigned))
			sig, e := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, h[:])
			if e != nil {
				http.Error(w, "signature failure", 500)
				return
			}
			p.exchanges++
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "owned-access-token", "token_type": "Bearer", "expires_in": 60, "id_token": unsigned + "." + enc(sig)})
		default:
			http.NotFound(w, r)
		}
	}))
	p.issuer = p.server.URL + "/application/o/gotth-mail/"
	p.ca = filepath.Join(dir, "owned-ca.pem")
	p.secretFile = filepath.Join(dir, "oidc-secret.private")
	if e := os.WriteFile(p.ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: p.server.Certificate().Raw}), 0600); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(p.secretFile, []byte("owned-synthetic-client-secret"), 0600); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(p.server.Close)
	return p
}
func (p *bOIDC) env(origin, authority string) []string {
	return []string{"SSL_CERT_FILE=" + p.ca, "SSL_CERT_DIR=/nonexistent-owned-ca-dir", "GOTTH_MAIL_IDENTITY_RUNTIME_CONFIG_FILE=" + authority, "GOTTH_MAIL_AUTHENTIK_ISSUER=" + p.issuer, "GOTTH_MAIL_AUTHENTIK_CLIENT_ID=gotth-mail", "GOTTH_MAIL_AUTHENTIK_CLIENT_SECRET_FILE=" + p.secretFile, "GOTTH_MAIL_AUTHENTIK_REDIRECT_URI=" + origin + "/api/v1/oidc/callback", "GOTTH_MAIL_SCIM_EXTERNAL_URL=" + origin + "/scim/v2"}
}
func bSeedProtocol(t *testing.T, db *sql.DB, issuer string) string {
	t.Helper()
	scope := identityruntime.Scope("b-scim")
	// Public reconciler owns opaque ID, canonical data, version and index creation.
	// Store-only fixture preparation deliberately precedes the legacy role fence;
	// it does not run a production authority projection as the fixture owner.
	registry, e := gotthscim.NewRegistry(gotthscim.DefaultDefinitions())
	if e != nil {
		t.Fatal(e)
	}
	reconciler, e := gotthscim.NewReconciler(&scimstore.SQLStore{DB: db}, registry, nil, nil)
	if e != nil {
		t.Fatal(e)
	}
	data, e := json.Marshal(map[string]any{"schemas": []string{gotthscim.UserSchema}, "userName": testMailbox, "active": true, "displayName": "Owned"})
	if e != nil {
		t.Fatal(e)
	}
	result, e := reconciler.Reconcile(context.Background(), gotthscim.ReconcileRequest{Scope: scope, Manager: "b-scim", Resources: []gotthscim.DesiredResource{{ResourceType: "User", ExternalID: testSubject, Data: data}}})
	if e != nil || result.Created != 1 || result.Updated != 0 || result.Deleted != 0 {
		t.Fatal("public SCIM fixture creation", e)
	}
	var resourceID string
	if e = db.QueryRow("SELECT id FROM scim_resources WHERE scope=$1 AND resource_type='User' AND external_id=$2 AND manager='b-scim'", scope, testSubject).Scan(&resourceID); e != nil || resourceID == "" {
		t.Fatal("generated SCIM fixture ID", e)
	}
	groupExec(t, db, "UPDATE mailboxes SET scim_resource_id=$1 WHERE id='00000000-0000-4000-8000-000000000182'", resourceID)
	var boundID string
	if e = db.QueryRow("SELECT m.scim_resource_id FROM identity_refs ir JOIN mailboxes m ON m.id=ir.mailbox_id WHERE ir.id=$1 AND ir.issuer=$2 AND ir.subject=$3", testIdentity, issuer, testSubject).Scan(&boundID); e != nil || boundID != resourceID {
		t.Fatal("exact synthetic User binding", e)
	}

	ids, e := identity.NewSQLService(context.Background(), db)
	if e != nil {
		t.Fatal(e)
	}
	if e = ids.AddToken("b-scim", "scim_client", "owned-synthetic-scim-token"); e != nil {
		t.Fatal(e)
	}
	groupExec(t, db, "INSERT INTO mailboxes(id,domain_id,local_part,enabled,created_at,updated_at) VALUES ('00000000-0000-4000-8000-000000000184',$1,'ordinary',true,now(),now())", testDomain)
	groupExec(t, db, "INSERT INTO identity_refs(id,provider,issuer,subject,mailbox_id,created_at,updated_at) VALUES ('00000000-0000-4000-8000-000000000185','authentik',$1,'ordinary-subject','00000000-0000-4000-8000-000000000184',now(),now())", issuer)
	seedUTC := time.Now().UTC()
	groupExec(t, db, "INSERT INTO sessions(id,identity_ref_id,csrf_secret_hash,auth_method,created_at,expires_at,last_seen_at) VALUES ('ordinary-session','00000000-0000-4000-8000-000000000185','hash','oidc',$1,$2,$1)", seedUTC.Add(-time.Minute), seedUTC.Add(time.Hour))
	csrf := sha256.Sum256([]byte("owned-seeded-csrf"))
	groupExec(t, db, "UPDATE sessions SET csrf_secret_hash=$1 WHERE id IN ('existing-session','ordinary-session')", base64.RawURLEncoding.EncodeToString(csrf[:]))
	// Exact OIDC insert/update, SCIM User update/index/upsert and history insert powers.
	groupExec(t, db, "GRANT SELECT,INSERT,UPDATE ON oidc_login_states TO b_current,b_rollback; GRANT INSERT ON identity_refs,sessions,domains,mailboxes TO b_current,b_rollback; GRANT UPDATE ON scim_resources TO b_current,b_rollback; GRANT SELECT,INSERT ON scim_index_contracts TO b_current,b_rollback; GRANT SELECT,INSERT,DELETE ON scim_resource_indexes TO b_current,b_rollback")
	return resourceID
}
func (p *bOIDC) exercise(t *testing.T, db *sql.DB, origin, kind, resourceID string, trusted *http.Client) string {
	t.Helper()
	client := &http.Client{Transport: trusted.Transport, Timeout: 3 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	csrfCookies := map[string]string{"existing-session": "owned-seeded-csrf", "ordinary-session": "owned-seeded-csrf"}
	call := func(method, path, body, cookie, bearer string) ([]byte, *http.Response) {
		t.Helper()
		req, e := http.NewRequest(method, origin+path, strings.NewReader(body))
		if e != nil {
			t.Fatal(e)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-GOTTH-Mail-Browser-Binding", "owned-browser-binding")
		if cookie != "" {
			req.AddCookie(&http.Cookie{Name: "gotth_mail_session", Value: cookie})
			req.AddCookie(&http.Cookie{Name: "gotth_mail_csrf", Value: csrfCookies[cookie]})
		}
		if bearer != "" {
			req.Header.Set("Authorization", "Bearer "+bearer)
		}
		res, e := client.Do(req)
		if e != nil {
			t.Fatal(e)
		}
		b, e := io.ReadAll(io.LimitReader(res.Body, 1<<20))
		res.Body.Close()
		if e != nil {
			t.Fatal(e)
		}
		return b, res
	}
	body, res := call("GET", "/api/v1/oidc/login", "", "", "")
	if res.StatusCode != 200 {
		t.Fatal("actual login start", res.StatusCode)
	}
	var start authn.LoginStart
	if e := json.Unmarshal(body, &start); e != nil {
		t.Fatal(e)
	}
	u, e := url.Parse(start.URL)
	if e != nil {
		t.Fatal(e)
	}
	p.mu.Lock()
	p.nonce = u.Query().Get("nonce")
	p.challenge = u.Query().Get("code_challenge")
	before := p.exchanges
	p.mu.Unlock()
	callback, _ := json.Marshal(map[string]string{"state": start.StateID, "code": "owned-code", "redirect_uri": origin + "/api/v1/oidc/callback"})
	_, res = call("POST", "/api/v1/oidc/callback", string(callback), "", "")
	if res.StatusCode != 200 {
		t.Fatal("actual signed OIDC callback", res.StatusCode)
	}
	p.mu.Lock()
	exchanges := p.exchanges
	p.mu.Unlock()
	if exchanges != before+1 {
		t.Fatal("provider exchange not observed")
	}
	sid := ""
	for _, c := range res.Cookies() {
		if c.Name == "gotth_mail_session" {
			sid = c.Value
		}
	}
	for _, c := range res.Cookies() {
		if c.Name == "gotth_mail_csrf" {
			csrfCookies[sid] = c.Value
		}
	}
	if sid == "" {
		t.Fatal("no actual session cookie")
	}
	var identityID string
	if e := db.QueryRow("SELECT identity_ref_id::text FROM sessions WHERE id=$1 AND revoked_at IS NULL", sid).Scan(&identityID); e != nil || identityID != testIdentity {
		t.Fatal("login exact identity binding", e)
	}
	_, res = call("POST", "/api/v1/oidc/callback", string(callback), "", "")
	if res.StatusCode == 200 {
		t.Fatal("callback replay accepted")
	}
	// These routes construct their actor from actual SQL BoundSession. 503 means
	// authority accepted and optional backend unavailable, not an admin operation.
	for _, x := range []struct {
		label  string
		cookie string
		code   int
		marker string
	}{{"fresh_callback", sid, 503, "extension administrator unavailable"}, {"existing_seeded", "existing-session", 503, "extension administrator unavailable"}, {"ordinary_seeded", "ordinary-session", 403, "admin authorization required"}} {
		var zone string
		var created, expires time.Time
		nowUTC := time.Now().UTC()
		if e := db.QueryRow("SELECT current_setting('TimeZone'),created_at,expires_at FROM sessions WHERE id=$1", x.cookie).Scan(&zone, &created, &expires); e != nil {
			t.Fatal("session diagnostic query failed")
		}
		t.Logf("SESSION_METADATA kind=%s case=%s DBtimezone=%s created=%s expires=%s GoUTC=%s created_le_now=%t expires_gt_now=%t", kind, x.label, zone, created.Format(time.RFC3339Nano), expires.Format(time.RFC3339Nano), nowUTC.Format(time.RFC3339Nano), !created.After(nowUTC), expires.After(nowUTC))
		if created.After(nowUTC) || !expires.After(nowUTC) {
			t.Fatal("invalid fixture/session timestamp predicate", kind, x.label)
		}
		b, res := call("GET", "/admin/extensions", "", x.cookie, "")
		reason := "unclassified"
		for _, known := range []string{"identity session required", "identity session is invalid", "identity CSRF binding is invalid", "admin authorization required", "extension administrator unavailable"} {
			if strings.TrimSpace(string(b)) == known {
				reason = known
			}
		}
		t.Logf("BROWSER_ORACLE kind=%s case=%s status=%d reason=%s", kind, x.label, res.StatusCode, reason)
		if res.StatusCode != x.code || !bytes.Contains(b, []byte(x.marker)) {
			t.Fatal("browser role boundary", kind, x.label, res.StatusCode, x.code, reason)
		}
	}
	_, res = call("GET", "/identity/app-passwords", "", sid, "")
	if res.StatusCode != 200 {
		t.Fatal("actual bound session self-service", res.StatusCode)
	}
	_, res = call("GET", "/scim/v2/Users/"+url.PathEscape(resourceID), "", "", "wrong")
	if res.StatusCode != 401 {
		t.Fatal("SCIM wrong token", res.StatusCode)
	}
	_, res = call("GET", "/scim/v2/Users/"+url.PathEscape(resourceID), "", "", "owned-synthetic-scim-token")
	if res.StatusCode != 200 {
		t.Fatal("SCIM exact User read", res.StatusCode)
	}
	patch := fmt.Sprintf("{\"schemas\":[\"urn:ietf:params:scim:api:messages:2.0:PatchOp\"],\"Operations\":[{\"op\":\"replace\",\"path\":\"displayName\",\"value\":%q}]}", kind)
	_, res = call("PATCH", "/scim/v2/Users/"+url.PathEscape(resourceID), patch, "", "owned-synthetic-scim-token")
	if res.StatusCode != 200 {
		t.Fatal("SCIM actual mutation", kind, res.StatusCode)
	}
	var display string
	if e := db.QueryRow("SELECT display_name FROM mailboxes WHERE scim_resource_id=$1", resourceID).Scan(&display); e != nil || display != kind {
		t.Fatal("SCIM mailbox persistence", e)
	}
	t.Logf("ACTUAL_PROTOCOL_PASS %s trusted-TLS+RS256+nonce+PKCE authenticated stub exchange, callback replay denial, SQL session, browser global allow/ordinary deny, SCIM token/read/mutation", kind)
	return sid
}

// The product listens on HTTP behind its documented HTTPS ingress. This owned
// ephemeral TLS frontend replaces no host listener/configuration.
func bFrontend(t *testing.T, addr string) *httptest.Server {
	t.Helper()
	target, e := url.Parse("http://" + addr)
	if e != nil {
		t.Fatal(e)
	}
	s := httptest.NewTLSServer(httputil.NewSingleHostReverseProxy(target))
	t.Cleanup(s.Close)
	return s
}

func bDaemon(t *testing.T, addr string) {
	t.Helper()
	for _, x := range []struct{ domain, want string }{{"example.test", "200 1\n"}, {"missing.test", "500 not found\n"}} {
		c, e := net.DialTimeout("tcp", addr, time.Second)
		if e != nil {
			t.Fatal(e)
		}
		c.SetDeadline(time.Now().Add(time.Second))
		fmt.Fprintf(c, "get %s\n", x.domain)
		got, e := bufio.NewReader(c).ReadString('\n')
		c.Close()
		if e != nil || got != x.want {
			t.Fatal("native daemon domain map", e)
		}
	}
	t.Log("ACTUAL_DAEMON_PASS known/unknown domain socket replies")
}
