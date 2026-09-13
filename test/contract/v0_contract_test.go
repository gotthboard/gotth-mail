package contract

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestV0ArtifactsExist(t *testing.T) {
	paths := []string{"../../Dockerfile", "../../compose/reference/docker-compose.yml", "../../proto/gotth/mail/plugin/v1/plugin.proto", "../../migrations/0001_initial.sql"}
	for _, p := range paths {
		if _, err := os.Stat(p); err != nil {
			t.Fatalf("missing %s: %v", p, err)
		}
	}
}
func TestComposeContainsAuthentikAndNoDockerSocket(t *testing.T) {
	b, err := os.ReadFile(filepath.Clean("../../compose/reference/docker-compose.yml"))
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	if !strings.Contains(s, "authentik:") {
		t.Fatal("compose missing authentik service")
	}
	if strings.Contains(s, "/var/run/docker.sock") {
		t.Fatal("docker socket mount forbidden")
	}
}
func TestProtoDefinesPluginControl(t *testing.T) {
	b, err := os.ReadFile(filepath.Clean("../../proto/gotth/mail/plugin/v1/plugin.proto"))
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	for _, needle := range []string{"service PluginControl", "rpc Health", "rpc Version", "rpc Capabilities"} {
		if !strings.Contains(s, needle) {
			t.Fatalf("proto missing %s", needle)
		}
	}
}
