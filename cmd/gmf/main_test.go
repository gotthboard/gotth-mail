package main

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestCLIStagedRenderApplyConfirmationGate(t *testing.T) {
	root := t.TempDir()
	cfg := filepath.Join(root, "config.yaml")
	staged := filepath.Join(root, "staged")
	applied := filepath.Join(root, "applied")
	if err := os.WriteFile(cfg, []byte(fmt.Sprintf(`server:
  public_url: "https://mail.example.test"
  listen: ":8080"
  environment: "development"
database:
  dsn: "postgres://db"
tls:
  mode: "manual"
  cert_path: "cert.pem"
  key_path: "key.pem"
authentik:
  enabled: true
  base_url: "https://auth.example.test"
  oidc_client_id: "gmf"
  scim_base_url: "https://auth.example.test/scim"
roles:
  global_admin_group: "admins"
  domain_manager_group: "managers"
  scoped_domain_group_prefix: "domain-"
render:
  staging_dir: %q
  applied_dir: %q
plugins:
  - name: "stub-dns"
    seam: "dns"
    image: "stub:v0"
    endpoint: "dns:9443"
`, staged, applied)), 0644); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"render", "--config", cfg}); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(staged)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("staged entries=%d", len(entries))
	}
	id := entries[0].Name()
	if err := run([]string{"apply", "--config", cfg}); err == nil {
		t.Fatal("missing --confirm accepted")
	}
	if err := run([]string{"apply", "--config", cfg, "--confirm", "wrong"}); err == nil {
		t.Fatal("wrong --confirm accepted")
	}
	if err := run([]string{"apply", "--config", cfg, "--confirm", id}); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(applied, "current"))
	if err != nil {
		t.Fatal(err)
	}
	if got := string(b); got != id+"\n" {
		t.Fatalf("applied current=%q want %q", got, id+"\n")
	}
}

func TestCLIDoctorTextAndJSON(t *testing.T) {
	if err := run([]string{"doctor", "--format", "text"}); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"doctor", "--format", "json"}); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"doctor", "--format", "xml"}); err == nil {
		t.Fatal("unsupported doctor format accepted")
	}
}

func TestCLIAuditRetentionPreviewApplyRequiresConfirmation(t *testing.T) {
	if err := run([]string{"audit", "retention", "preview", "--policy", "older-than-90d"}); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"audit", "retention", "apply", "--policy", "older-than-90d"}); err == nil {
		t.Fatal("missing confirmation accepted")
	}
	if err := run([]string{"audit", "retention", "apply", "--policy", "older-than-90d", "--confirm", "wrong"}); err == nil {
		t.Fatal("wrong confirmation accepted")
	}
}
