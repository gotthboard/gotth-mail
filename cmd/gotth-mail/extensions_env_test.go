package main

import (
	"bufio"
	"context"
	"database/sql"
	"fmt"
	"forgejo/gotthboard/gotth-mail/internal/extensionsruntime"
	"forgejo/gotthboard/gotth-mail/internal/httpui"
	"forgejo/gotthboard/gotth-mail/internal/identity"
	"net"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"forgejo/gotthboard/gotth-mail/internal/api"
	"forgejo/gotthboard/gotth-mail/internal/audit"
	"forgejo/gotthboard/gotth-mail/internal/extensionsadmin"
	"forgejo/gotthboard/gotth-mail/internal/notification"
	"forgejo/gotthboard/gotth-mail/internal/store"
	"forgejo/gotthboard/gotth-mail/internal/testpg"
)

func TestConfigureExtensionsRequiresPrivateExactMasterKey(t *testing.T) {
	t.Setenv("GOTTH_MAIL_EXTENSION_MASTER_KEY_FILE", "")
	server := api.Server{}
	if err := configureExtensionsFromEnv(&server); err != nil || server.Extensions != nil {
		t.Fatalf("empty configuration err=%v service=%v", err, server.Extensions)
	}

	path := filepath.Join(t.TempDir(), "extension.key")
	if err := os.WriteFile(path, []byte(strings.Repeat("a", 64)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GOTTH_MAIL_EXTENSION_MASTER_KEY_FILE", path)
	if err := configureExtensionsFromEnv(&server); err == nil {
		t.Fatal("accepted extension key without database")
	}
	server.AuditDB = &sql.DB{}
	if err := configureExtensionsFromEnv(&server); err != nil {
		t.Fatal(err)
	}
	if server.Extensions == nil {
		t.Fatal("extension administrator not configured")
	}

	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	server.Extensions = nil
	if err := configureExtensionsFromEnv(&server); err == nil || server.Extensions != nil {
		t.Fatal("accepted world-readable extension key")
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "extension-link.key")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GOTTH_MAIL_EXTENSION_MASTER_KEY_FILE", link)
	if err := configureExtensionsFromEnv(&server); err == nil {
		t.Fatal("accepted symlinked extension key")
	}
	t.Setenv("GOTTH_MAIL_EXTENSION_MASTER_KEY_FILE", path)
	if err := os.WriteFile(path, []byte("short"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := configureExtensionsFromEnv(&server); err == nil {
		t.Fatal("accepted short extension key")
	}
}

func TestExtensionRoots(t *testing.T) {
	db := testpg.DB(t, store.MigrateSQL)
	base := t.TempDir()
	key := filepath.Join(base, "extension.key")
	if err := os.WriteFile(key, []byte(strings.Repeat("a", 64)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	artifactRoot := filepath.Join(base, "artifacts")
	runtimeRoot := filepath.Join(base, "runtime")
	if err := os.Mkdir(artifactRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(runtimeRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GOTTH_MAIL_EXTENSION_ARTIFACT_ROOT", artifactRoot)
	t.Setenv("GOTTH_MAIL_EXTENSION_RUNTIME_ROOT", runtimeRoot)
	t.Setenv("GOTTH_MAIL_EXTENSION_MASTER_KEY_FILE", "")
	server := api.Server{AuditDB: db}
	if err := configureExtensionsFromEnv(&server); err == nil {
		t.Fatal("runtime roots accepted without master key")
	}
	t.Setenv("GOTTH_MAIL_EXTENSION_MASTER_KEY_FILE", key)
	t.Setenv("GOTTH_MAIL_EXTENSION_RUNTIME_ROOT", "")
	if err := configureExtensionsFromEnv(&server); err == nil {
		t.Fatal("partial runtime roots accepted")
	}
	t.Setenv("GOTTH_MAIL_EXTENSION_RUNTIME_ROOT", runtimeRoot)
	if err := configureExtensionsFromEnv(&server); err != nil {
		t.Fatalf("complete runtime rejected: %v", err)
	}
	if server.Extensions == nil || server.Extensions.Runtime == nil || server.NotificationService == nil || server.NotificationRecorder == nil || server.PluginHealth == nil {
		t.Fatal("extension runtime was not wired completely")
	}

	conflict := api.Server{AuditDB: &sql.DB{}, NotificationService: &notification.Service{}}
	if err := configureExtensionsFromEnv(&conflict); err == nil {
		t.Fatal("managed webhook runtime accepted beside static notification plugin")
	}
	if err := os.Chmod(runtimeRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	server = api.Server{AuditDB: &sql.DB{}}
	if err := configureExtensionsFromEnv(&server); err == nil {
		t.Fatal("world-accessible extension runtime root accepted")
	}
}

func TestRestartWiring(t *testing.T) {
	db := testpg.DB(t, store.MigrateSQL)
	base := t.TempDir()
	key := filepath.Join(base, "key")
	if err := os.WriteFile(key, []byte(strings.Repeat("k", 32)), 0600); err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{"a", "r"} {
		if err := os.Mkdir(filepath.Join(base, dir), 0700); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("GOTTH_MAIL_EXTENSION_MASTER_KEY_FILE", key)
	t.Setenv("GOTTH_MAIL_EXTENSION_ARTIFACT_ROOT", filepath.Join(base, "a"))
	t.Setenv("GOTTH_MAIL_EXTENSION_RUNTIME_ROOT", filepath.Join(base, "r"))
	s, err := extensionsadmin.NewService(db, []byte(strings.Repeat("k", 32)), nil)
	if err != nil {
		t.Fatal(err)
	}
	id := "00000000-0000-4000-8000-000000000026"
	_, err = s.Install(context.Background(), audit.ActorRef{Type: "api_token", ID: "restart"}, extensionsadmin.InstallRequest{InstanceID: id, ExtensionID: "notification.restart", Repository: "https://github.com/gotthboard/gotth-extension-restart", ArtifactPin: "sha256:" + strings.Repeat("1", 64), ManifestDigest: strings.Repeat("2", 64), GrantDigest: strings.Repeat("3", 64), SessionDigest: strings.Repeat("4", 64), Metadata: extensionsadmin.Metadata{Schema: extensionsadmin.MetadataSchema}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec("UPDATE extension_instances SET enabled=true,routed=true,lifecycle='ready',tested_revision=configuration_revision"); err != nil {
		t.Fatal(err)
	}
	server := api.Server{AuditDB: db}
	if err := configureExtensionsFromEnv(&server); err != nil {
		t.Fatal(err)
	}
	got, err := server.Extensions.Get(context.Background(), id)
	if err != nil || got.Routed || !got.Enabled || got.Lifecycle != "degraded" || got.HealthCode != "extension.restart-required" {
		t.Fatalf("stale startup state %#v err=%v", got, err)
	}
	var n int
	if err := db.QueryRow("SELECT count(*) FROM audit_events WHERE action='extension.reconcile'").Scan(&n); err != nil || n != 1 {
		t.Fatalf("reconcile audit %d err=%v", n, err)
	}
}

func TestBlockedExtensionIsolation(t *testing.T) {
	db := testpg.DB(t, store.MigrateSQL)
	base := t.TempDir()
	key := filepath.Join(base, "key")
	if err := os.WriteFile(key, []byte(strings.Repeat("k", 32)), 0600); err != nil {
		t.Fatal(err)
	}
	a, r := filepath.Join(base, "a"), filepath.Join(base, "r")
	if err := os.Mkdir(a, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(r, 0700); err != nil {
		t.Fatal(err)
	}
	leftover := filepath.Join(r, "unknown")
	if err := os.WriteFile(leftover, []byte("preserved"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GOTTH_MAIL_EXTENSION_MASTER_KEY_FILE", key)
	t.Setenv("GOTTH_MAIL_EXTENSION_ARTIFACT_ROOT", a)
	t.Setenv("GOTTH_MAIL_EXTENSION_RUNTIME_ROOT", r)
	seed, err := extensionsadmin.NewService(db, []byte(strings.Repeat("k", 32)), nil)
	if err != nil {
		t.Fatal(err)
	}
	id := "00000000-0000-4000-8000-000000000028"
	before, err := seed.Install(context.Background(), audit.ActorRef{Type: "api_token", ID: "isolation"}, extensionsadmin.InstallRequest{InstanceID: id, ExtensionID: "notification.isolation", Repository: "https://github.com/gotthboard/gotth-extension-isolation", ArtifactPin: "sha256:" + strings.Repeat("1", 64), ManifestDigest: strings.Repeat("2", 64), GrantDigest: strings.Repeat("3", 64), SessionDigest: strings.Repeat("4", 64), Metadata: extensionsadmin.Metadata{Schema: extensionsadmin.MetadataSchema}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("UPDATE extension_instances SET enabled=true,routed=true,lifecycle='ready',health_code='extension.ready',tested_revision=configuration_revision WHERE instance_id=$1", id); err != nil {
		t.Fatal(err)
	}
	server := referenceServer()
	server.AuditDB = db
	if err := configureExtensionsFromEnv(&server); err != nil {
		t.Fatal("extension leftovers prevent Mail startup", err)
	}
	health, err := server.PluginHealth(context.Background(), extensionsruntime.ExtensionID)
	if err == nil || health.Healthy || health.Message != "extension.runtime-blocked" {
		t.Errorf("missing visible quarantine %#v %v", health, err)
	}
	ids := identity.NewService("example.test")
	if err := ids.AddTokenWithScopes("fixture", "api_token", "dev-admin-token", "ops:admin"); err != nil {
		t.Fatal(err)
	}
	ui := httpui.HandlerWithAdminIdentitySessionsAndExtensions(referenceAdminStore(), ids, server.Authz, nil, nil, server.Extensions)
	req := httptest.NewRequest("GET", "/admin/extensions", nil)
	req.Header.Set("Authorization", "Bearer dev-admin-token")
	res := httptest.NewRecorder()
	ui.ServeHTTP(res, req)
	if res.Code != 200 || !strings.Contains(res.Body.String(), "operator must verify prior processes stopped") {
		t.Errorf("blocked administrator missing actionable state: %d %s", res.Code, res.Body.String())
	}
	instances, err := server.Extensions.List(context.Background())
	if err != nil || len(instances) != 1 {
		t.Fatalf("inventory unavailable/incomplete: %d %v", len(instances), err)
	}
	got := instances[0]
	if !got.Enabled || got.Routed || got.Lifecycle != "degraded" || got.HealthCode != "extension.runtime-blocked" || got.TestedRevision != got.ConfigurationRev || got.ArtifactPin != before.ArtifactPin || got.ManifestDigest != before.ManifestDigest || got.GrantDigest != before.GrantDigest || got.SessionDigest != before.SessionDigest {
		t.Fatalf("quarantine lost intent/binding or kept route: %#v", got)
	}
	var audits int
	if err := db.QueryRow("SELECT count(*) FROM audit_events WHERE action='extension.reconcile' AND resource_id=$1 AND after_redacted_json::jsonb->>'health_code'='extension.runtime-blocked' AND after_redacted_json::jsonb->>'routed'='false'", id).Scan(&audits); err != nil || audits != 1 {
		t.Fatalf("blocked reconcile audit=%d err=%v", audits, err)
	}
	// Exercise the actual configured TCP listener, not a direct handler/pipe.
	t.Setenv("GOTTH_MAIL_POSTFIX_POLICY_LISTEN", "127.0.0.1:0")
	for _, key := range []string{"GOTTH_MAIL_POSTFIX_DOMAIN_MAP_LISTEN", "GOTTH_MAIL_POSTFIX_MAILBOX_MAP_LISTEN", "GOTTH_MAIL_POSTFIX_ALIAS_MAP_LISTEN"} {
		t.Setenv(key, "")
	}
	listeners, err := configurePostfixListenersFromEnv(server.Daemon)
	if err != nil {
		t.Fatal("Postfix startup blocked", err)
	}
	defer func() {
		for _, listener := range listeners {
			listener.Close()
		}
	}()
	if len(listeners) != 1 {
		t.Fatalf("listeners=%d", len(listeners))
	}
	conn, err := net.DialTimeout("tcp", listeners[0].Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := fmt.Fprint(conn, "request=smtpd_access_policy\nprotocol_state=RCPT\ninstance=quarantine\nsender=outside@example.net\nrecipient=smoke@example.test\n\n"); err != nil {
		t.Fatal(err)
	}
	response, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil || strings.TrimSpace(response) != "action=DUNNO" {
		t.Fatalf("Postfix unavailable during quarantine: %q %v", response, err)
	}
	for _, path := range []string{"/healthz", "/readyz", "/api/v1/status"} {
		res := httptest.NewRecorder()
		server.Handler().ServeHTTP(res, httptest.NewRequest("GET", path, nil))
		if res.Code != 200 {
			t.Fatalf("unrelated HTTP unavailable %s %d", path, res.Code)
		}
	}
	if data, err := os.ReadFile(leftover); err != nil || string(data) != "preserved" {
		t.Fatal("unknown runtime file changed", err)
	}
}
