package main

import (
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"forgejo/gotthboard/gotth-mail/internal/api"
	"forgejo/gotthboard/gotth-mail/internal/notification"
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

func TestConfigureExtensionsRuntimeRequiresCompleteIsolatedRoots(t *testing.T) {
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
	server := api.Server{AuditDB: &sql.DB{}}
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
