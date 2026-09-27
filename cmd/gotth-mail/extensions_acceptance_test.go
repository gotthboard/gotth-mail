package main

// Test equipment only: operator-verified alpha.1/alpha.2 staging, not a product installer.
// Run using scripts/extensions-delivery-acceptance.sh in an isolated namespace.
import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"forgejo/gotthboard/gotth-mail/internal/audit"
	"forgejo/gotthboard/gotth-mail/internal/authn"
	"forgejo/gotthboard/gotth-mail/internal/authz"
	"forgejo/gotthboard/gotth-mail/internal/extensionsadmin"
	"forgejo/gotthboard/gotth-mail/internal/extensionsruntime"
	"forgejo/gotthboard/gotth-mail/internal/identity"
	"forgejo/gotthboard/gotth-mail/internal/notification"
	"forgejo/gotthboard/gotth-mail/internal/plugin"
	"forgejo/gotthboard/gotth-mail/internal/store"
	"forgejo/gotthboard/gotth-mail/internal/testpg"
	extensioncore "github.com/gotthboard/gotth-extensions/pkg/extensions"
)

// Expected digest comes from admitted alpha.1 verification, never the archive itself.
const acceptanceArchiveSHA = "5cb6043ca200acfa67d4c6a85e0c1ba070c51dc550cacca7ce538021c8d9e83a"
const acceptanceArchiveBSHA = "d3b79e577bc68aedcb83b8c3cc378341cf8610db514c751be3ff331df9a8937a"
const acceptanceBodyLimit = 64 << 10

func acceptanceCheck(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
func acceptanceRandom(t *testing.T) string {
	t.Helper()
	b := make([]byte, 32)
	_, err := rand.Read(b)
	acceptanceCheck(t, err)
	return hex.EncodeToString(b)
}
func acceptanceUUID(t *testing.T) string {
	t.Helper()
	b := make([]byte, 16)
	_, err := rand.Read(b)
	acceptanceCheck(t, err)
	b[6] = b[6]&15 | 64
	b[8] = b[8]&63 | 128
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[:4], b[4:6], b[6:8], b[8:10], b[10:])
}

// Closed two-pin fixture: no caller-selected digest or generic installer.
func acceptanceArchive(data []byte, version string) (map[string][]byte, error) {
	expected := acceptanceArchiveSHA
	switch version {
	case "1.0.0-alpha.1":
	case "1.0.0-alpha.2":
		expected = acceptanceArchiveBSHA
	default:
		return nil, errors.New("unapproved release")
	}
	acceptancePackage := "gotth-extension-webhook-" + version + "-linux-amd64"
	if len(data) > 8<<20 || fmt.Sprintf("%x", sha256.Sum256(data)) != expected {
		return nil, errors.New("archive digest/size mismatch")
	}
	z, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer z.Close()
	tr := tar.NewReader(io.LimitReader(z, 16<<20))
	files := map[string][]byte{}
	directory := false
	allowed := map[string]bool{"LICENSE": true, "SHA256SUMS": true, "configuration-metadata.json": true, "manifest.json": true, "gotth-extension-webhook": true}
	for count := 0; ; count++ {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		if count >= 6 {
			return nil, errors.New("too many archive entries")
		}
		if h.Name == acceptancePackage+"/" && h.Typeflag == tar.TypeDir && !directory {
			directory = true
			continue
		}
		name := strings.TrimPrefix(h.Name, acceptancePackage+"/")
		if h.Name != acceptancePackage+"/"+name || !allowed[name] || files[name] != nil || h.Typeflag != tar.TypeReg || h.Size < 0 || h.Size > 12<<20 {
			return nil, errors.New("unexpected archive member")
		}
		b, err := io.ReadAll(tr)
		if err != nil {
			return nil, err
		}
		files[name] = b
	}
	if !directory || len(files) != 5 {
		return nil, errors.New("incomplete archive")
	}
	seen := map[string]bool{}
	for _, line := range strings.Split(strings.TrimSpace(string(files["SHA256SUMS"])), "\n") {
		p := strings.Split(line, "  ")
		if len(p) != 2 || p[1] == "SHA256SUMS" || !allowed[p[1]] || seen[p[1]] || fmt.Sprintf("%x", sha256.Sum256(files[p[1]])) != p[0] {
			return nil, errors.New("member checksum mismatch")
		}
		seen[p[1]] = true
	}
	if len(seen) != 4 {
		return nil, errors.New("incomplete checksums")
	}
	return files, nil
}

// Login is explicitly mocked. Production cookie binding, role authorization and CSRF remain real.
type acceptanceSessions struct {
	*authn.Store
	bound authn.BoundSession
}

func (s acceptanceSessions) PutIdentitySession(context.Context, authn.Identity, authn.Session) (authn.Session, error) {
	return authn.Session{}, errors.New("login outside acceptance fixture")
}
func (s acceptanceSessions) BoundSession(_ context.Context, id string, now time.Time) (authn.BoundSession, bool) {
	return s.bound, id == s.bound.ID && now.Before(s.bound.ExpiresAt)
}

// Independent receiver verifier bounds raw bytes before authenticating the exact wire body.
func acceptanceMAC(body []byte, signature string, key []byte) bool {
	if len(body) > acceptanceBodyLimit || !strings.HasPrefix(signature, "sha256=") {
		return false
	}
	got, err := hex.DecodeString(strings.TrimPrefix(signature, "sha256="))
	if err != nil {
		return false
	}
	mac := hmac.New(sha256.New, key)
	mac.Write(body)
	return hmac.Equal(got, mac.Sum(nil))
}
func TestExtensionAcceptanceReceiverBounds(t *testing.T) {
	key := []byte(acceptanceRandom(t))
	for _, n := range []int{acceptanceBodyLimit - 1, acceptanceBodyLimit, acceptanceBodyLimit + 1, 2 * acceptanceBodyLimit} {
		b := bytes.Repeat([]byte("x"), n)
		mac := hmac.New(sha256.New, key)
		mac.Write(b)
		sig := "sha256=" + hex.EncodeToString(mac.Sum(nil))
		if acceptanceMAC(b, sig, key) != (n <= acceptanceBodyLimit) {
			t.Fatalf("size %d", n)
		}
		if acceptanceMAC(b, sig, []byte(acceptanceRandom(t))) {
			t.Fatal("wrong key accepted")
		}
	}
	for _, sig := range []string{"", "sha256=zz", "sha256=00"} {
		if acceptanceMAC(nil, sig, key) {
			t.Fatal("malformed MAC accepted")
		}
	}
}

func TestExtensionRealArchiveDelivery(t *testing.T) { acceptanceLifecycle(t, false) }

func TestExtensionRealArchiveUpdateRollback(t *testing.T) { acceptanceLifecycle(t, true) }

func acceptanceLifecycle(t *testing.T, updateRollback bool) {
	acceptanceLifecycleDriver(t, updateRollback, nil)
}

// The optional test-only driver replaces actions, never the real setup or oracles.
func acceptanceLifecycleDriver(t *testing.T, updateRollback bool, browser func(acceptanceBrowserStart)) {
	archive := os.Getenv("GOTTH_MAIL_ACCEPTANCE_ARCHIVE")
	if archive == "" {
		t.Skip("opt-in packaged acceptance; use namespace runner")
	}
	if updateRollback && os.Getenv("GOTTH_MAIL_ACCEPTANCE_ARCHIVE_B") == "" {
		t.Skip("opt-in two-archive acceptance; pass candidate B to runner")
	}
	if os.Getenv("GOTTH_MAIL_ACCEPTANCE_NAMESPACE") != "1" {
		t.Fatal("private namespace runner required")
	}
	for _, tool := range []string{"initdb", "postgres", "createdb"} {
		_, err := exec.LookPath(tool)
		acceptanceCheck(t, err)
	}
	archiveFile, err := os.Open(archive)
	acceptanceCheck(t, err)
	data, err := io.ReadAll(io.LimitReader(archiveFile, (8<<20)+1))
	acceptanceCheck(t, archiveFile.Close())
	acceptanceCheck(t, err)
	files, err := acceptanceArchive(data, "1.0.0-alpha.1")
	acceptanceCheck(t, err)
	bad := bytes.Clone(data)
	bad[len(bad)/2] ^= 1
	if _, err := acceptanceArchive(bad, "1.0.0-alpha.1"); err == nil {
		t.Fatal("altered archive accepted")
	}
	if _, err := acceptanceArchive(make([]byte, (8<<20)+1), "1.0.0-alpha.1"); err == nil {
		t.Fatal("oversized archive accepted")
	}
	var manifest extensioncore.Manifest
	acceptanceCheck(t, json.Unmarshal(files["manifest.json"], &manifest))
	canonical, err := extensioncore.CanonicalManifest(manifest)
	acceptanceCheck(t, err)
	if !bytes.Equal(canonical, files["manifest.json"]) || manifest.Version != "1.0.0-alpha.1" || manifest.ID != extensionsruntime.ExtensionID {
		t.Fatal("noncanonical/wrong release manifest")
	}
	var metadata extensionsadmin.Metadata
	acceptanceCheck(t, json.Unmarshal(files["configuration-metadata.json"], &metadata))
	acceptanceCheck(t, extensionsadmin.ValidateMetadata(metadata))
	id := acceptanceUUID(t)
	md, err := extensioncore.ManifestDigest(manifest)
	acceptanceCheck(t, err)
	grant := extensioncore.Grant{Schema: extensioncore.GrantSchema, InstanceID: id, ExtensionID: manifest.ID, ManifestDigest: md, Capabilities: manifest.Capabilities, Interfaces: []extensioncore.InterfaceGrant{{Name: extensionsruntime.Interface, Major: 1, Minor: 0}}, Secrets: []string{extensionsruntime.SecretSlot}}
	profile := extensioncore.HostProfile{Protocols: []extensioncore.VersionRange{{Name: extensioncore.ControlName, Major: 1, MinMinor: 0, MaxMinor: 0}}, Interfaces: []extensioncore.VersionRange{{Name: extensionsruntime.Interface, Major: 1, MinMinor: 0, MaxMinor: 0}}}
	session, err := extensioncore.Negotiate(manifest, grant, profile)
	acceptanceCheck(t, err)
	t.Logf("archive=%s binary=%x manifest=%s instance=%s grant=%s session=%s", acceptanceArchiveSHA, sha256.Sum256(files["gotth-extension-webhook"]), md, id, session.GrantDigest, session.Fingerprint)
	// Short namespace-private paths avoid Unix socket pathname overflow.
	base, err := os.MkdirTemp("/tmp", "gd-")
	acceptanceCheck(t, err)
	t.Cleanup(func() { acceptanceCheck(t, os.RemoveAll(base)) })
	a, r := filepath.Join(base, "a"), filepath.Join(base, "r")
	acceptanceCheck(t, os.Mkdir(a, 0700))
	acceptanceCheck(t, os.Mkdir(r, 0700))
	stage := filepath.Join(a, acceptanceArchiveSHA)
	acceptanceCheck(t, os.Mkdir(stage, 0700))
	for name, b := range files {
		mode := os.FileMode(0400)
		if name == "gotth-extension-webhook" {
			mode = 0500
		}
		acceptanceCheck(t, os.WriteFile(filepath.Join(stage, name), b, mode))
	}
	acceptanceCheck(t, os.WriteFile(filepath.Join(stage, "artifact-pin"), []byte("sha256:"+acceptanceArchiveSHA), 0400))
	// Publish read-only only after verification. Cleanup restores owner write permission.
	acceptanceCheck(t, os.Chmod(stage, 0500))
	t.Cleanup(func() { acceptanceCheck(t, os.Chmod(stage, 0700)) })
	out, err := exec.Command(filepath.Join(stage, "gotth-extension-webhook"), "--version").CombinedOutput()
	acceptanceCheck(t, err)
	if !strings.Contains(string(out), "1.0.0-alpha.1") {
		t.Fatal("binary version mismatch")
	}
	t.Logf("version=%s", strings.TrimSpace(string(out)))
	master := filepath.Join(base, "master")
	acceptanceCheck(t, os.WriteFile(master, []byte(acceptanceRandom(t)), 0600))
	db := testpg.DB(t, store.MigrateSQL)
	var version int
	acceptanceCheck(t, db.QueryRow("SELECT current_setting('server_version_num')::int").Scan(&version))
	if version < 160000 || version >= 170000 {
		t.Fatalf("PG16 required: %d", version)
	}
	t.Logf("postgres=%d", version)
	server := referenceServer()
	server.AuditDB = db
	server.Identity = identity.NewService("example.test")
	bearer, csrf, sid := acceptanceRandom(t), acceptanceRandom(t), acceptanceRandom(t)
	acceptanceCheck(t, server.Identity.AddTokenWithScopes("acceptance-registration", "api_token", bearer, "ops:admin"))
	csrfSum := sha256.Sum256([]byte(csrf))
	server.OIDCStore = acceptanceSessions{Store: authn.NewStore(), bound: authn.BoundSession{Session: authn.Session{ID: sid, IdentityRefID: acceptanceUUID(t), CreatedAt: time.Now().Add(-time.Minute), ExpiresAt: time.Now().Add(time.Hour), CSRFSecretHash: base64.RawURLEncoding.EncodeToString(csrfSum[:])}, Mailbox: "admin@example.test", Roles: []authz.RoleAssignment{{Role: authz.RoleGlobalAdmin}}}}
	t.Setenv("GOTTH_MAIL_EXTENSION_MASTER_KEY_FILE", master)
	t.Setenv("GOTTH_MAIL_EXTENSION_ARTIFACT_ROOT", a)
	t.Setenv("GOTTH_MAIL_EXTENSION_RUNTIME_ROOT", r)
	acceptanceCheck(t, configureExtensionsFromEnv(&server))
	handler := runtimeMux(server)
	install := extensionsadmin.InstallRequest{InstanceID: id, ExtensionID: manifest.ID, Repository: extensionsruntime.Repository, ArtifactPin: "sha256:" + acceptanceArchiveSHA, ManifestDigest: md, GrantDigest: session.GrantDigest, SessionDigest: session.Fingerprint, Capabilities: grant.Capabilities, Interfaces: []string{extensionsruntime.Interface}, SecretSlots: grant.Secrets, Metadata: metadata}
	payload, err := json.Marshal(install)
	acceptanceCheck(t, err)
	req := httptest.NewRequest("POST", "/api/v1/extensions", bytes.NewReader(payload))
	req.Header.Set("Authorization", "Bearer "+bearer)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != 201 {
		t.Fatalf("registration status=%d", w.Code)
	}
	var installed extensionsadmin.Instance
	acceptanceCheck(t, json.Unmarshal(w.Body.Bytes(), &installed))
	if installed.Enabled || installed.Routed || installed.Lifecycle != "discovered" {
		t.Fatal("registration admitted runtime")
	}
	form := func(values url.Values) string {
		t.Helper()
		req := httptest.NewRequest("POST", "/admin/extensions/"+id, strings.NewReader(values.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.AddCookie(&http.Cookie{Name: "gotth_mail_session", Value: sid})
		req.AddCookie(&http.Cookie{Name: "gotth_mail_csrf", Value: csrf})
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		if w.Code != 200 {
			t.Fatalf("form %s status=%d", values.Get("action"), w.Code)
		}
		return w.Body.String()
	}
	action := func(name string) {
		t.Helper()
		body := form(url.Values{"action": {name}, "csrf_token": {csrf}})
		if !strings.Contains(body, "extension operation accepted") {
			t.Fatalf("action %s rejected", name)
		}
	}
	// Cleanup always goes through the authorized Disable path, including assertion failures.
	t.Cleanup(func() {
		action("disable")
		entries, err := os.ReadDir(r)
		acceptanceCheck(t, err)
		if len(entries) != 0 {
			t.Errorf("runtime files remain: %d", len(entries))
		}
	})
	current := func() extensionsadmin.Instance {
		t.Helper()
		item, err := server.Extensions.Get(context.Background(), id)
		acceptanceCheck(t, err)
		return item
	}
	emptyRuntime := func() {
		t.Helper()
		entries, err := os.ReadDir(r)
		acceptanceCheck(t, err)
		if len(entries) != 0 {
			t.Fatal("unexpected live runtime files")
		}
	}
	key := acceptanceRandom(t)
	type receiverExpectation struct {
		Body      map[string]any
		Key, Path string
	}
	var expected atomic.Value
	var requests, accepted, rejected atomic.Int32
	receiver := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		requests.Add(1)
		b, err := io.ReadAll(io.LimitReader(req.Body, acceptanceBodyLimit+1))
		var got map[string]any
		decodeErr := json.Unmarshal(b, &got)
		want, ready := expected.Load().(receiverExpectation)
		valid := err == nil && decodeErr == nil && req.Method == "POST" && req.Header.Get("Content-Type") == "application/json" && req.TLS != nil && req.TLS.Version >= tls.VersionTLS12 && acceptanceMAC(b, req.Header.Get("X-GOTTH-Signature"), []byte(want.Key)) && ready && req.URL.Path == want.Path && reflect.DeepEqual(got, want.Body) && req.Header.Get("X-GOTTH-Alert-ID") == got["id"] && req.Header.Get("X-GOTTH-Correlation-ID") == got["correlation_id"]
		if !valid {
			rejected.Add(1)
			w.WriteHeader(403)
			return
		}
		accepted.Add(1)
		t.Logf("receiver alert=%s body_sha256=%x authenticated=true", got["id"], sha256.Sum256(b))
		w.WriteHeader(204)
	}))
	cert, err := tls.LoadX509KeyPair(os.Getenv("GOTTH_MAIL_ACCEPTANCE_CERT"), os.Getenv("GOTTH_MAIL_ACCEPTANCE_KEY"))
	acceptanceCheck(t, err)
	receiver.TLS = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	receiver.StartTLS()
	t.Cleanup(receiver.Close)
	var untrustedHTTP atomic.Int32
	untrusted := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { untrustedHTTP.Add(1); w.WriteHeader(204) }))
	untrusted.Config.ErrorLog = log.New(io.Discard, "", 0)
	untrusted.StartTLS()
	t.Cleanup(untrusted.Close)
	configure := func(endpoint, secret, timeout string) {
		t.Helper()
		before := current()
		values := url.Values{"action": {"configure-preview"}, "csrf_token": {csrf}, "field.webhook.endpoint": {endpoint}, "field.webhook.timeout-seconds": {timeout}, "field.webhook.hmac-key": {secret}}
		body := form(values)
		if strings.Contains(body, secret) {
			t.Fatal("secret rendered")
		}
		p := regexp.MustCompile(`name="preview_id" value="([^"]+)"`).FindStringSubmatch(body)
		c := regexp.MustCompile(`<code>(confirm-[a-f0-9]+)</code>`).FindStringSubmatch(body)
		if len(p) != 2 || len(c) != 2 {
			t.Fatal("configuration preview missing")
		}
		if current().ConfigurationRev != before.ConfigurationRev {
			t.Fatal("preview mutated configuration")
		}
		emptyRuntime()
		values.Set("action", "configure-apply")
		values.Set("preview_id", p[1])
		values.Set("confirmation", c[1])
		body = form(values)
		if !strings.Contains(body, "extension operation accepted") || strings.Contains(body, secret) {
			t.Fatal("configuration not accepted/redacted")
		}
		if current().ConfigurationRev != before.ConfigurationRev+1 {
			t.Fatal("configuration revision not advanced")
		}
	}
	testEnable := func() {
		t.Helper()
		n := requests.Load()
		action("test")
		item := current()
		if item.Enabled || item.Routed || item.TestedRevision != item.ConfigurationRev || requests.Load() != n {
			t.Fatal("Test is readiness only")
		}
		emptyRuntime()
		action("enable")
		item = current()
		if !item.Enabled || !item.Routed {
			t.Fatal("enable did not admit routing")
		}
		entries, err := os.ReadDir(r)
		acceptanceCheck(t, err)
		if len(entries) != 1 {
			t.Fatal("expected one runtime directory")
		}
		runDir := filepath.Join(r, entries[0].Name())
		for _, name := range []string{"", "secrets", "config.json", "binding.json", "service.token", "secrets/webhook.hmac-key", "extension.sock"} {
			info, err := os.Lstat(filepath.Join(runDir, name))
			acceptanceCheck(t, err)
			if info.Mode().Perm()&0077 != 0 {
				t.Fatalf("runtime path %q is not private", name)
			}
		}
		if len(filepath.Join(runDir, "extension.sock")) > 100 {
			t.Fatal("socket path exceeds contract")
		}
	}
	receiverPath := "/"
	send := func(label string) (notification.DeliveryRecord, error) {
		t.Helper()
		alert := notification.Alert{ID: acceptanceUUID(t), Class: "acceptance." + label, Severity: notification.SeverityInfo, Title: "Packaged acceptance", Summary: "Synthetic alert", CorrelationID: acceptanceUUID(t), Resource: notification.ResourceRef{Type: "fixture", ID: id}, Details: map[string]string{"zeta": "last", "alpha": "first"}}
		expected.Store(receiverExpectation{Key: key, Path: receiverPath, Body: map[string]any{"schema": "gotth.extension.webhook.alert.v1", "id": alert.ID, "class": alert.Class, "severity": "info", "title": alert.Title, "summary": alert.Summary, "correlation_id": alert.CorrelationID, "resource_type": "fixture", "resource_id": id, "details": []any{map[string]any{"key": "alpha", "value": "first"}, map[string]any{"key": "zeta", "value": "last"}}}})
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer cancel()
		rec, err := server.NotificationService.SendAlert(ctx, alert)
		stored, ok, readErr := (notification.SQLRecorder{DB: db}).Get(context.Background(), alert.ID)
		acceptanceCheck(t, readErr)
		if !ok || !reflect.DeepEqual(stored, rec) {
			t.Fatal("SQL delivery does not match service result")
		}
		t.Logf("delivery label=%s alert=%s correlation=%s status=%s reason=%s transport=%s verification=%s", label, alert.ID, alert.CorrelationID, stored.Status, stored.Reason, stored.Evidence.Transport, stored.Evidence.VerificationResult)
		return rec, err
	}
	if browser != nil {
		var observation *nativeTestRuntime
		var update *nativeUpdateSetup
		if mode := os.Getenv("GOTTH_MAIL_BROWSER_MODE"); mode == "connection-test" || mode == "activation" || mode == "update" {
			configure(receiver.URL, key, "2") // Admitted handler-driven SETUP, not browser coverage.
			if mode == "activation" || mode == "update" {
				action("test")
				emptyRuntime()
			} // SETUP, not native Test credit.
			original := server.Extensions.Runtime
			observation = &nativeTestRuntime{Runtime: original, root: r, executable: filepath.Join(stage, "gotth-extension-webhook"), expectedSHA: sha256.Sum256(files["gotth-extension-webhook"])}
			if mode == "activation" {
				supervisor, ok := original.(*extensionsruntime.Supervisor)
				if !ok {
					t.Fatal("real routing supervisor missing")
				}
				observation.routeHealth = func(ctx context.Context) (plugin.HealthResponse, error) {
					return supervisor.Health(ctx, extensionsruntime.ExtensionID)
				}
			}
			if mode == "update" {
				_, filesB, stageB, mdB, grantB, sessionB := acceptanceStageB(t, a, manifest, metadata, grant, profile)
				supervisor, ok := original.(*extensionsruntime.Supervisor)
				if !ok {
					t.Fatal("real update supervisor missing")
				}
				update = &nativeUpdateSetup{Target: extensionsadmin.UpdateInput{ArtifactPin: "sha256:" + acceptanceArchiveBSHA, ManifestDigest: mdB, GrantDigest: sessionB.GrantDigest, SessionDigest: sessionB.Fingerprint, Capabilities: grantB.Capabilities, Interfaces: []string{extensionsruntime.Interface}, SecretSlots: grantB.Secrets, Metadata: metadata}, Executable: filepath.Join(stageB, "gotth-extension-webhook"), SHA: sha256.Sum256(filesB["gotth-extension-webhook"])}
				update.Route = func(ctx context.Context) (plugin.HealthResponse, error) {
					return supervisor.Health(ctx, extensionsruntime.ExtensionID)
				}
				update.TestB = func(ctx context.Context, observer *nativeTestRuntime) error {
					server.Extensions.Runtime = observer
					defer func() { server.Extensions.Runtime = observation }()
					_, err := server.Extensions.Test(ctx, audit.ActorRef{Type: "oidc_subject", ID: server.OIDCStore.(acceptanceSessions).bound.IdentityRefID}, id)
					return err
				}
			}
			server.Extensions.Runtime = observation
			defer func() { server.Extensions.Runtime = original }() // Restore before registered Disable cleanup.
		}
		browser(acceptanceBrowserStart{Update: update, TestRuntime: observation, Handler: handler, DB: db, ID: id, Session: sid, CSRF: csrf, Current: current, EmptyRuntime: emptyRuntime, Requests: requests.Load, Endpoint: receiver.URL, Secret: key, MasterFile: master, RuntimeRoot: r, Executable: filepath.Join(stage, "gotth-extension-webhook"), ActorID: server.OIDCStore.(acceptanceSessions).bound.IdentityRefID})
		return
	}
	configure(untrusted.URL, key, "1")
	testEnable()
	rec, sendErr := send("untrusted")
	if sendErr == nil || rec.Status != notification.StatusFailedRetryable || untrustedHTTP.Load() != 0 {
		t.Fatal("untrusted TLS negative control failed")
	}
	action("disable")
	emptyRuntime()
	configure(receiver.URL, acceptanceRandom(t), "1")
	testEnable()
	rec, sendErr = send("wrong-key")
	acceptanceCheck(t, sendErr)
	if rec.Status != notification.StatusFailedPermanent || rec.Reason != "receiver_rejected" || rejected.Load() != 1 || accepted.Load() != 0 {
		t.Fatal("wrong HMAC negative control failed")
	}
	action("disable")
	emptyRuntime()
	configure(receiver.URL, key, "1")
	testEnable()
	rec, sendErr = send("positive")
	acceptanceCheck(t, sendErr)
	if rec.Status != notification.StatusDelivered || rec.Reason != "receiver_accepted" || rec.Evidence.Transport != "https-webhook" || rec.Evidence.VerificationResult != "hmac_sha256" || accepted.Load() != 1 || requests.Load() != 2 {
		t.Fatal("authenticated delivery not proven")
	}
	action("disable")
	emptyRuntime()
	item := current()
	if item.Enabled || item.Routed {
		t.Fatal("disable retained route")
	}
	rec, sendErr = send("disabled")
	if sendErr == nil || rec.Status != notification.StatusFailedRetryable || requests.Load() != 2 {
		t.Fatal("disabled runtime delivered")
	}
	if !updateRollback {
		t.Log("PASS real registration/configure/readiness/enable/HTTPS-HMAC/SQL/disable; login mocked; no browser claim")
		return
	}
	archiveB, filesB, stageB, mdB, grantB, sessionB := acceptanceStageB(t, a, manifest, metadata, grant, profile)
	// /proc is namespace-private. Match the actual child executable and hash its open inode,
	// not the registry pin or a separate --version process. Require exactly one live match.
	liveIdentity := func(dir string, expectedBinary []byte) {
		t.Helper()
		entries, err := os.ReadDir("/proc")
		acceptanceCheck(t, err)
		matches := 0
		for _, entry := range entries {
			if entry.Name() == "" || entry.Name()[0] < '0' || entry.Name()[0] > '9' {
				continue
			}
			exe := filepath.Join("/proc", entry.Name(), "exe")
			target, err := os.Readlink(exe)
			if err != nil || target != filepath.Join(dir, "gotth-extension-webhook") {
				continue
			}
			matches++
			f, err := os.Open(exe)
			acceptanceCheck(t, err)
			h := sha256.New()
			_, err = io.Copy(h, io.LimitReader(f, (12<<20)+1))
			acceptanceCheck(t, f.Close())
			acceptanceCheck(t, err)
			want := sha256.Sum256(expectedBinary)
			if !bytes.Equal(h.Sum(nil), want[:]) {
				t.Fatal("live executable hash mismatch")
			}
			t.Logf("live executable pid=%s sha256=%x", entry.Name(), h.Sum(nil))
		}
		if matches != 1 {
			t.Fatalf("expected one pinned live child, got %d", matches)
		}
	}
	denied := func(values url.Values) {
		t.Helper()
		before := current()
		n := requests.Load()
		body := form(values)
		if strings.Contains(body, "extension operation accepted") || !reflect.DeepEqual(before, current()) || requests.Load() != n {
			t.Fatalf("denial failed: %s", values.Get("action"))
		}
	}
	previewFields := url.Values{"action": {"update-preview"}, "csrf_token": {csrf}, "artifact_pin": {"sha256:" + acceptanceArchiveBSHA}, "manifest_sha256": {mdB}, "grant_sha256": {sessionB.GrantDigest}, "session_sha256": {sessionB.Fingerprint}, "capabilities": {strings.Join(grantB.Capabilities, ",")}, "interfaces": {extensionsruntime.Interface}, "secret_slots": {extensionsruntime.SecretSlot}}
	action("enable")
	liveIdentity(stage, files["gotth-extension-webhook"])
	denied(previewFields)
	denied(url.Values{"action": {"rollback"}, "csrf_token": {csrf}, "confirmation": {"rollback " + manifest.ID + " to sha256:" + acceptanceArchiveSHA}})
	action("disable")
	emptyRuntime()
	snapshotA := current()
	before := current()
	n := requests.Load()
	body := form(previewFields)
	if !reflect.DeepEqual(before, current()) || requests.Load() != n {
		t.Fatal("update preview mutated state or delivered")
	}
	emptyRuntime()
	for _, value := range []string{acceptanceArchiveBSHA, mdB, sessionB.GrantDigest, sessionB.Fingerprint} {
		if !strings.Contains(body, value) {
			t.Fatal("preview lost exact target")
		}
	}
	p := regexp.MustCompile(`name="preview_id" value="([^"]+)"`).FindStringSubmatch(body)
	c := regexp.MustCompile(`<code>(confirm-[a-f0-9]+)</code>`).FindStringSubmatch(body)
	if len(p) != 2 || len(c) != 2 {
		t.Fatal("update confirmation missing")
	}
	apply := url.Values{"action": {"update-apply"}, "csrf_token": {csrf}, "preview_id": {p[1]}, "confirmation": {"wrong"}}
	denied(apply)
	apply.Set("confirmation", c[1])
	apply.Set("preview_id", p[1]+"-tampered")
	denied(apply)
	apply.Set("preview_id", p[1])
	body = form(apply)
	if !strings.Contains(body, "extension operation accepted") {
		t.Fatal("update rejected")
	}
	b := current()
	if b.ArtifactPin != "sha256:"+acceptanceArchiveBSHA || b.PreviousArtifact != snapshotA.ArtifactPin || b.ManifestDigest != mdB || b.GrantDigest != sessionB.GrantDigest || b.SessionDigest != sessionB.Fingerprint || b.TestedRevision != 0 || b.Enabled || b.Routed || b.Lifecycle != "stopped" || b.ConfigurationRev != snapshotA.ConfigurationRev+1 {
		t.Fatal("B update state mismatch")
	}
	denied(apply) // consumed preview cannot be replayed
	denied(url.Values{"action": {"enable"}, "csrf_token": {csrf}})
	emptyRuntime()
	successfulSend := func(label string) {
		t.Helper()
		n, a := requests.Load(), accepted.Load()
		rec, err := send(label)
		acceptanceCheck(t, err)
		if rec.Status != notification.StatusDelivered || rec.Reason != "receiver_accepted" || rec.Evidence.Transport != "https-webhook" || rec.Evidence.VerificationResult != "hmac_sha256" || requests.Load() != n+1 || accepted.Load() != a+1 {
			t.Fatal("authenticated delivery missing")
		}
	}
	testEnable()
	liveIdentity(stageB, filesB["gotth-extension-webhook"])
	successfulSend("b")
	// A previous snapshot survives subsequent B configuration edits, but secrets are not snapshots.
	denied(url.Values{"action": {"rollback"}, "csrf_token": {csrf}, "confirmation": {"rollback " + manifest.ID + " to " + snapshotA.ArtifactPin}})
	action("disable")
	emptyRuntime()
	oldKey := key
	rotatedKey := acceptanceRandom(t)
	key = rotatedKey
	receiverPath = "/candidate-b"
	configure(receiver.URL+receiverPath, key, "2")
	configuredB := current()
	if reflect.DeepEqual(configuredB.Configuration, snapshotA.Configuration) {
		t.Fatal("B configuration must differ meaningfully")
	}
	testEnable()
	liveIdentity(stageB, filesB["gotth-extension-webhook"])
	successfulSend("b-rotated")
	action("disable")
	emptyRuntime()
	beforeRollback := current()
	rollback := url.Values{"action": {"rollback"}, "csrf_token": {csrf}, "confirmation": {"wrong"}}
	denied(rollback)
	rollback.Set("confirmation", "rollback "+manifest.ID+" to "+snapshotA.ArtifactPin)
	body = form(rollback)
	if !strings.Contains(body, "extension operation accepted") {
		t.Fatal("rollback rejected")
	}
	restored := current()
	if restored.ArtifactPin != snapshotA.ArtifactPin || restored.PreviousArtifact != b.ArtifactPin || restored.ManifestDigest != snapshotA.ManifestDigest || restored.GrantDigest != snapshotA.GrantDigest || restored.SessionDigest != snapshotA.SessionDigest || !reflect.DeepEqual(restored.Metadata, snapshotA.Metadata) || !reflect.DeepEqual(restored.Configuration, snapshotA.Configuration) || !reflect.DeepEqual(restored.Capabilities, snapshotA.Capabilities) || !reflect.DeepEqual(restored.Interfaces, snapshotA.Interfaces) || !reflect.DeepEqual(restored.SecretSlots, snapshotA.SecretSlots) || restored.TestedRevision != 0 || restored.Enabled || restored.Routed || restored.Lifecycle != "stopped" || restored.ConfigurationRev != beforeRollback.ConfigurationRev+1 {
		t.Fatal("rollback snapshot mismatch")
	}
	denied(url.Values{"action": {"enable"}, "csrf_token": {csrf}})
	emptyRuntime()
	receiverPath = "/"
	testEnable()
	liveIdentity(stage, files["gotth-extension-webhook"])
	// A must no longer authenticate with the old key after rollback.
	key = oldKey
	rec, sendErr = send("a-old-key-rejected")
	acceptanceCheck(t, sendErr)
	if rec.Status != notification.StatusFailedPermanent || rec.Reason != "receiver_rejected" {
		t.Fatal("rollback resurrected old secret")
	}
	// Retain the new value from configuration in the fixture, not from runtime private files.
	key = rotatedKey
	successfulSend("a-rollback-retained-key")
	action("disable")
	emptyRuntime()
	n = requests.Load()
	rec, sendErr = send("rollback-disabled")
	if sendErr == nil || rec.Status != notification.StatusFailedRetryable || requests.Load() != n {
		t.Fatal("rollback disable delivered")
	}
	for path, want := range map[string]string{archive: acceptanceArchiveSHA, archiveB: acceptanceArchiveBSHA} {
		f, err := os.Open(path)
		acceptanceCheck(t, err)
		h := sha256.New()
		_, err = io.Copy(h, f)
		acceptanceCheck(t, f.Close())
		acceptanceCheck(t, err)
		if fmt.Sprintf("%x", h.Sum(nil)) != want {
			t.Fatal("source archive changed")
		}
	}
	t.Log("PASS A->B->A actual live binaries, confirmed update/rollback, restored A configuration, retained rotated secret; login mocked; no browser claim")
}

// Exactly the admitted B verification/staging block; not a generic artifact loader.
func acceptanceStageB(t *testing.T, a string, manifest extensioncore.Manifest, metadata extensionsadmin.Metadata, grant extensioncore.Grant, profile extensioncore.HostProfile) (string, map[string][]byte, string, string, extensioncore.Grant, extensioncore.Session) {
	t.Helper()
	// Candidate B is an independently admitted version-only test artifact, not a release.
	archiveB := os.Getenv("GOTTH_MAIL_ACCEPTANCE_ARCHIVE_B")
	f, err := os.Open(archiveB)
	acceptanceCheck(t, err)
	dataB, err := io.ReadAll(io.LimitReader(f, (8<<20)+1))
	acceptanceCheck(t, f.Close())
	acceptanceCheck(t, err)
	filesB, err := acceptanceArchive(dataB, "1.0.0-alpha.2")
	acceptanceCheck(t, err)
	if _, err := acceptanceArchive(dataB, "1.0.0-alpha.1"); err == nil {
		t.Fatal("B admitted under A pin")
	}
	var manifestB extensioncore.Manifest
	acceptanceCheck(t, json.Unmarshal(filesB["manifest.json"], &manifestB))
	canonicalB, err := extensioncore.CanonicalManifest(manifestB)
	acceptanceCheck(t, err)
	if !bytes.Equal(canonicalB, filesB["manifest.json"]) || manifestB.Version != "1.0.0-alpha.2" || manifestB.ID != manifest.ID {
		t.Fatal("wrong B manifest")
	}
	var metadataB extensionsadmin.Metadata
	acceptanceCheck(t, json.Unmarshal(filesB["configuration-metadata.json"], &metadataB))
	acceptanceCheck(t, extensionsadmin.ValidateMetadata(metadataB))
	if !reflect.DeepEqual(metadataB, metadata) {
		t.Fatal("version-only candidate metadata changed")
	}
	mdB, err := extensioncore.ManifestDigest(manifestB)
	acceptanceCheck(t, err)
	binaryB := fmt.Sprintf("%x", sha256.Sum256(filesB["gotth-extension-webhook"]))
	if mdB != "4093f2b17c2b8062d0f3ceb27480c77865289ec883c642798cd19352a8cab9ea" || binaryB != "6248244fa56bf39554d961019d40d71ece7a68eb5801eca0ef87602272818652" {
		t.Fatal("B member provenance mismatch")
	}
	grantB := grant
	grantB.ManifestDigest = mdB
	grantB.Capabilities = manifestB.Capabilities
	sessionB, err := extensioncore.Negotiate(manifestB, grantB, profile)
	acceptanceCheck(t, err)
	stageB := filepath.Join(a, acceptanceArchiveBSHA)
	acceptanceCheck(t, os.Mkdir(stageB, 0700))
	for name, b := range filesB {
		mode := os.FileMode(0400)
		if name == "gotth-extension-webhook" {
			mode = 0500
		}
		acceptanceCheck(t, os.WriteFile(filepath.Join(stageB, name), b, mode))
	}
	acceptanceCheck(t, os.WriteFile(filepath.Join(stageB, "artifact-pin"), []byte("sha256:"+acceptanceArchiveBSHA), 0400))
	acceptanceCheck(t, os.Chmod(stageB, 0500))
	t.Cleanup(func() { acceptanceCheck(t, os.Chmod(stageB, 0700)) })
	outB, err := exec.Command(filepath.Join(stageB, "gotth-extension-webhook"), "--version").CombinedOutput()
	acceptanceCheck(t, err)
	if strings.TrimSpace(string(outB)) != "1.0.0-alpha.2" {
		t.Fatal("B binary version mismatch")
	}
	t.Logf("B archive=%s binary=%s manifest=%s grant=%s session=%s version=%s", acceptanceArchiveBSHA, binaryB, mdB, sessionB.GrantDigest, sessionB.Fingerprint, strings.TrimSpace(string(outB)))
	return archiveB, filesB, stageB, mdB, grantB, sessionB
}
