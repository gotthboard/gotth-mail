package extensionsruntime

import (
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"forgejo/gotthboard/gotth-mail/internal/extensionsadmin"
	"forgejo/gotthboard/gotth-mail/internal/notification"
)

func TestNewRequiresSafeRoots(t *testing.T) {
	base, err := os.MkdirTemp("", "gtew-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(base) })
	artifactRoot := filepath.Join(base, "artifacts")
	runtimeRoot := filepath.Join(base, "runtime")
	if err := os.Mkdir(artifactRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(runtimeRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := New(artifactRoot, runtimeRoot); err != nil {
		t.Fatalf("safe roots rejected: %v", err)
	}
	if err := os.Chmod(runtimeRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := New(artifactRoot, runtimeRoot); err == nil {
		t.Fatal("world-accessible runtime root accepted")
	}
	if err := os.Chmod(runtimeRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "runtime-link")
	if err := os.Symlink(runtimeRoot, link); err != nil {
		t.Fatal(err)
	}
	if _, err := New(artifactRoot, link); err == nil {
		t.Fatal("symlinked runtime root accepted")
	}
}

func TestRuntimeConfigurationIsClosed(t *testing.T) {
	encoded, err := runtimeConfiguration(map[string]any{"webhook.endpoint": "https://receiver.example.test/hook", "webhook.timeout-seconds": float64(10)})
	if err != nil || !strings.Contains(string(encoded), `"schema":"gotth.extension.webhook.config.v1"`) {
		t.Fatalf("valid configuration rejected: %s %v", encoded, err)
	}
	for name, values := range map[string]map[string]any{
		"unknown":  {"webhook.endpoint": "https://receiver.example.test", "webhook.timeout-seconds": 10, "extra": true},
		"fraction": {"webhook.endpoint": "https://receiver.example.test", "webhook.timeout-seconds": 1.5},
		"missing":  {"webhook.timeout-seconds": 10},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := runtimeConfiguration(values); err == nil {
				t.Fatal("invalid configuration accepted")
			}
		})
	}
}

func TestWebhookProcessLifecycle(t *testing.T) {
	binary := os.Getenv("GOTTH_EXTENSION_WEBHOOK_TEST_BINARY")
	manifestDigest := os.Getenv("GOTTH_EXTENSION_WEBHOOK_TEST_MANIFEST_SHA256")
	if binary == "" || manifestDigest == "" {
		t.Skip("independent webhook extension artifact not supplied")
	}
	binaryInfo, err := os.Stat(binary)
	if err != nil || !binaryInfo.Mode().IsRegular() {
		t.Fatalf("invalid extension test binary: %v", err)
	}
	base, err := os.MkdirTemp("", "gtew-lifecycle-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(base) })
	artifactRoot := filepath.Join(base, "artifacts")
	runtimeRoot := filepath.Join(base, "runtime")
	if err := os.Mkdir(artifactRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(runtimeRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte("independent-webhook-alpha-artifact"))
	pin := fmt.Sprintf("sha256:%x", digest[:])
	install := filepath.Join(artifactRoot, strings.TrimPrefix(pin, "sha256:"))
	if err := os.Mkdir(install, 0o755); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(install, executableName)
	data, err := os.ReadFile(binary)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, data, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(install, "artifact-pin"), []byte(pin+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	supervisor, err := New(artifactRoot, runtimeRoot)
	if err != nil {
		t.Fatal(err)
	}
	instance := extensionsadmin.Instance{
		InstanceID: "00000000-0000-4000-8000-000000000019", ExtensionID: ExtensionID, Repository: Repository,
		ArtifactPin: pin, ManifestDigest: manifestDigest, GrantDigest: strings.Repeat("2", 64), SessionDigest: strings.Repeat("3", 64),
		Capabilities: append([]string(nil), capabilities...), Interfaces: []string{Interface}, SecretSlots: []string{SecretSlot},
		Metadata:      webhookMetadata(),
		Configuration: map[string]any{"webhook.endpoint": "https://127.0.0.1:1/hook", "webhook.timeout-seconds": float64(1)}, ConfigurationRev: 2,
	}
	secrets := map[string][]byte{SecretSlot: []byte(strings.Repeat("k", 32))}
	if err := supervisor.Start(context.Background(), instance, secrets); err != nil {
		t.Fatalf("start failed: %v", err)
	}
	if health, err := supervisor.Probe(context.Background(), instance); err != nil || !health.Healthy || health.Code != "extension.ready" {
		t.Fatalf("probe failed: %#v %v", health, err)
	}
	if err := supervisor.AdmitRouting(context.Background(), instance); err != nil {
		t.Fatalf("routing admission failed: %v", err)
	}
	if health, err := supervisor.Health(context.Background(), ExtensionID); err != nil || !health.Healthy {
		t.Fatalf("routed health failed: %#v %v", health, err)
	}
	result, err := supervisor.SendAlert(context.Background(), notification.Alert{ID: "alert-1", Class: "doctor.failure", Severity: notification.SeverityCritical, Title: "Doctor failed", Summary: "Database unavailable", CorrelationID: "corr-1", Resource: notification.ResourceRef{Type: "doctor", ID: "local"}})
	if err == nil || result.Status != notification.StatusFailedRetryable || result.Reason != "notification_plugin_unavailable" {
		t.Fatalf("bounded transport failure not preserved: %#v %v", result, err)
	}
	if err := supervisor.Stop(context.Background(), instance); err != extensionsadmin.ErrConflict {
		t.Fatalf("stop before route revocation did not fail closed: %v", err)
	}
	if err := supervisor.RevokeRouting(context.Background(), instance); err != nil {
		t.Fatalf("routing revocation failed: %v", err)
	}
	if err := supervisor.Stop(context.Background(), instance); err != nil {
		t.Fatalf("stop failed: %v", err)
	}
	entries, err := os.ReadDir(runtimeRoot)
	if err != nil || len(entries) != 0 {
		t.Fatalf("runtime secrets were not removed: %v entries=%d", err, len(entries))
	}
}

func webhookMetadata() extensionsadmin.Metadata {
	minimumEndpoint, maximumEndpoint := int64(1), int64(2048)
	minimumTimeout, maximumTimeout := int64(1), int64(30)
	return extensionsadmin.Metadata{Schema: extensionsadmin.MetadataSchema, Fields: []extensionsadmin.Field{
		{Name: "webhook.endpoint", Label: "HTTPS webhook endpoint", Kind: extensionsadmin.FieldString, Required: true, Min: &minimumEndpoint, Max: &maximumEndpoint},
		{Name: "webhook.timeout-seconds", Label: "Request timeout in seconds", Kind: extensionsadmin.FieldInteger, Required: true, Min: &minimumTimeout, Max: &maximumTimeout, Default: float64(10)},
		{Name: SecretSlot, Label: "Webhook HMAC key", Kind: extensionsadmin.FieldSecret, Required: true},
	}}
}
