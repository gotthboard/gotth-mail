package main

import (
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"forgejo/gotthboard/gotth-mail/internal/api"
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
