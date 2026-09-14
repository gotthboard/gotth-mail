package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"forgejo/gotthboard/gotth-mail/internal/store"
	"forgejo/gotthboard/gotth-mail/internal/testpg"
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
  oidc_client_id: "gotth-mail"
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

func TestCLIAdoptionRequestRequiresAllOwnershipFields(t *testing.T) {
	request, err := adoptionRequest([]string{"identity", "adopt", "preview", "--mailbox", "member@example.test", "--subject", "subject", "--scope", "scope", "--manager", "manager"})
	if err != nil || request.Mailbox != "member@example.test" || request.Subject != "subject" || request.Scope != "scope" || request.Manager != "manager" {
		t.Fatalf("request=%#v err=%v", request, err)
	}
	if _, err := adoptionRequest([]string{"identity", "adopt", "preview", "--mailbox", "member@example.test"}); err == nil {
		t.Fatal("incomplete adoption request accepted")
	}
}

func TestCLISCIMTokenRequestRequiresProtectedFileInterface(t *testing.T) {
	actorID, path, err := scimTokenRequest([]string{"identity", "scim-token", "preview", "--id", "authentik-primary", "--secret-file", "/run/secrets/scim"})
	if err != nil || actorID != "authentik-primary" || path != "/run/secrets/scim" {
		t.Fatalf("actor=%q path=%q err=%v", actorID, path, err)
	}
	if _, _, err := scimTokenRequest([]string{"identity", "scim-token", "preview", "--id", "authentik-primary"}); err == nil {
		t.Fatal("missing secret file accepted")
	}
	if _, _, err := scimTokenRequest([]string{"identity", "scim-token", "preview", "--id", "authentik-primary", "--secret-file", "/run/secrets/scim", "--secret", "leak"}); err == nil {
		t.Fatal("argv secret accepted")
	}
}

func TestCLISCIMTokenPreviewApplyEndToEnd(t *testing.T) {
	db := testpg.DB(t, store.MigrateSQL)
	var port string
	if err := db.QueryRowContext(context.Background(), `SHOW port`).Scan(&port); err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	cfg := filepath.Join(root, "config.yaml")
	configBody := fmt.Sprintf(`server:
  public_url: "https://mail.example.test"
  listen: ":8080"
  environment: "development"
database:
  dsn: "postgres://gotth_mail@127.0.0.1:%s/gotth_mail?sslmode=disable"
tls:
  mode: "manual"
  cert_path: "cert.pem"
  key_path: "key.pem"
authentik:
  enabled: true
  base_url: "https://auth.example.test"
  oidc_client_id: "gotth-mail"
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
`, port, filepath.Join(root, "staged"), filepath.Join(root, "applied"))
	if err := os.WriteFile(cfg, []byte(configBody), 0o600); err != nil {
		t.Fatal(err)
	}
	secretPath := filepath.Join(root, "scim-token")
	secret := "cli-scim-bearer-0123456789ABCDEFGH"
	if err := os.WriteFile(secretPath, []byte(secret), 0o600); err != nil {
		t.Fatal(err)
	}
	previewArgs := []string{"identity", "scim-token", "preview", "--config", cfg, "--id", "authentik-primary", "--secret-file", secretPath}
	previewOutput, err := captureStdout(t, func() error { return run(previewArgs) })
	if err != nil {
		t.Fatal(err)
	}
	var plan struct {
		PlanID    string `json:"plan_id"`
		ActorID   string `json:"actor_id"`
		Operation string `json:"operation"`
	}
	if err := json.Unmarshal([]byte(previewOutput), &plan); err != nil {
		t.Fatal(err)
	}
	if plan.PlanID == "" || plan.ActorID != "authentik-primary" || plan.Operation != "create" || strings.Contains(previewOutput, secret) || strings.Contains(previewOutput, secretPath) {
		t.Fatalf("unsafe preview %q", previewOutput)
	}
	applyArgs := []string{"identity", "scim-token", "apply", "--config", cfg, "--id", "authentik-primary", "--secret-file", secretPath, "--confirm", plan.PlanID}
	applyOutput, err := captureStdout(t, func() error { return run(applyArgs) })
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(applyOutput, secret) || strings.Contains(applyOutput, secretPath) || !strings.Contains(applyOutput, `"changed":true`) {
		t.Fatalf("unsafe apply output %q", applyOutput)
	}
	var tokens, events int
	if err := db.QueryRow(`SELECT count(*) FROM tokens WHERE subject_id='authentik-primary' AND kind='scim_client' AND verifier <> $1`, secret).Scan(&tokens); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT count(*) FROM audit_events WHERE action='scim.token.create' AND resource_id='authentik-primary'`).Scan(&events); err != nil {
		t.Fatal(err)
	}
	if tokens != 1 || events != 1 {
		t.Fatalf("tokens=%d events=%d", tokens, events)
	}
}

func captureStdout(t *testing.T, fn func() error) (string, error) {
	t.Helper()
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	previous := os.Stdout
	os.Stdout = writer
	defer func() { os.Stdout = previous }()
	runErr := fn()
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	output, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := reader.Close(); err != nil {
		t.Fatal(err)
	}
	return string(output), runErr
}
