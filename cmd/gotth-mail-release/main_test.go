package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const releaseTestDigest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func TestReleaseArtifactIsDeterministicAndClosed(t *testing.T) {
	root := copyProductionConfiguration(t)
	spec := releaseSpec{
		ProductVersion: "1.0.0-alpha.1", TagObject: strings.Repeat("a", 40),
		SourceCommit: strings.Repeat("b", 40), ForgejoRefCommit: strings.Repeat("b", 40), GitHubRefCommit: strings.Repeat("b", 40),
		Images: map[string]string{}, Schema: schemaRange{Minimum: 17, Current: 17, Maximum: 17},
		Build: buildMetadata{GoVersion: "go1.26.5-X:nodwarf5", GOOS: "linux", GOARCH: "amd64", BuildDateEpoch: 1790000000},
	}
	for _, role := range roleRepositories {
		spec.Images[role.role] = releaseTestDigest
	}
	specPath := filepath.Join(t.TempDir(), "spec.json")
	encoded, err := json.Marshal(spec)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(specPath, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	first, second := filepath.Join(t.TempDir(), "one"), filepath.Join(t.TempDir(), "two")
	if err := buildRelease(specPath, root, first); err != nil {
		t.Fatal(err)
	}
	if err := buildRelease(specPath, root, second); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{archiveName, manifestName} {
		left, err := os.ReadFile(filepath.Join(first, name))
		if err != nil {
			t.Fatal(err)
		}
		right, err := os.ReadFile(filepath.Join(second, name))
		if err != nil || !bytes.Equal(left, right) {
			t.Fatalf("%s is not deterministic: %v", name, err)
		}
	}
	manifestBytes, err := os.ReadFile(filepath.Join(first, manifestName))
	if err != nil {
		t.Fatal(err)
	}
	var manifest releaseManifest
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		t.Fatal(err)
	}
	if manifest.Build != spec.Build {
		t.Fatalf("manifest build=%+v want=%+v", manifest.Build, spec.Build)
	}
	if err := os.WriteFile(filepath.Join(root, "unknown"), []byte("x"), 0o440); err != nil {
		t.Fatal(err)
	}
	if _, _, err := readConfiguration(root); err == nil {
		t.Fatal("unknown configuration member accepted")
	}
}

func TestReleaseConfigurationRejectsForbiddenMaterialAndSecretValues(t *testing.T) {
	tests := []struct {
		name    string
		member  string
		replace func([]byte) []byte
	}{
		{"fixture domain", "dovecot/dovecot.conf", func(value []byte) []byte { return append(value, []byte("# example.test\n")...) }},
		{"Mailu", "postfix/main.cf", func(value []byte) []byte { return append(value, []byte("# Mailu\n")...) }},
		{"Roundcube", "postfix/main.cf", func(value []byte) []byte { return append(value, []byte("# Roundcube\n")...) }},
		{"Telegram", "postfix/main.cf", func(value []byte) []byte { return append(value, []byte("# Telegram\n")...) }},
		{"private key", "dovecot/dovecot.conf", func(value []byte) []byte { return append(value, []byte("-----BEGIN PRIVATE KEY-----\n")...) }},
		{"front literal", "front/nginx.conf", func(value []byte) []byte {
			return bytes.ReplaceAll(value, []byte("@GOTTH_MAIL_FRONT_AUTH_TOKEN@"), []byte("literal_secret_value_0123456789012345"))
		}},
		{"Rspamd literal", "rspamd/override.inc", func(value []byte) []byte {
			return bytes.ReplaceAll(value, []byte("@GOTTH_MAIL_RSPAMD_CONTROLLER_TOKEN@"), []byte("literal_secret_value_0123456789012345"))
		}},
		{"environment literal", "control/environment", func(value []byte) []byte {
			return append(value, []byte("GOTTH_MAIL_AUTHENTIK_CLIENT_SECRET=literal\n")...)
		}},
		{"environment secret path", "control/environment", func(value []byte) []byte {
			return append(value, []byte("GOTTH_MAIL_AUTHENTIK_CLIENT_SECRET_FILE=literal\n")...)
		}},
		{"duplicate environment", "postfix/environment", func(value []byte) []byte { return append(value, []byte("GOTTH_MAIL_CORE_URL=http://other\n")...) }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root := copyProductionConfiguration(t)
			path := filepath.Join(root, filepath.FromSlash(test.member))
			value, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(path, 0o640); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, test.replace(value), 0o440); err != nil {
				t.Fatal(err)
			}
			if _, _, err := readConfiguration(root); err == nil {
				t.Fatal("forbidden production configuration accepted")
			}
		})
	}
}

func copyProductionConfiguration(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	for name := range requiredConfiguration {
		value, err := os.ReadFile(filepath.Join("..", "..", "configs", "production", filepath.FromSlash(name)))
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, value, 0o440); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func TestReleaseSpecRejectsDrift(t *testing.T) {
	path := filepath.Join(t.TempDir(), "spec.json")
	if err := os.WriteFile(path, []byte(`{"product_version":"1.0.0-alpha.0"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readSpec(path); err == nil {
		t.Fatal("invalid release identity accepted")
	}
}

func TestWriteAtomicNeverReplacesExistingOutput(t *testing.T) {
	path := filepath.Join(t.TempDir(), "artifact")
	if err := os.WriteFile(path, []byte("existing"), 0o440); err != nil {
		t.Fatal(err)
	}
	if err := writeAtomic(path, []byte("replacement"), 0o440); err == nil {
		t.Fatal("existing release output replaced")
	}
	value, err := os.ReadFile(path)
	if err != nil || string(value) != "existing" {
		t.Fatalf("existing output=%q error=%v", value, err)
	}
}

func TestReleaseSpecBindsActualBuildMetadata(t *testing.T) {
	images := map[string]string{}
	for _, role := range roleRepositories {
		images[role.role] = releaseTestDigest
	}
	for _, productVersion := range []string{"1.0.0-alpha.1", "1.0.0"} {
		payload := map[string]any{
			"product_version":    productVersion,
			"tag_object":         strings.Repeat("a", 40),
			"source_commit":      strings.Repeat("b", 40),
			"forgejo_ref_commit": strings.Repeat("b", 40),
			"github_ref_commit":  strings.Repeat("b", 40),
			"images":             images,
			"extensions":         []any{},
			"schema":             map[string]any{"minimum": 17, "current": 17, "maximum": 17},
			"build": map[string]any{
				"go_version":       "go1.26.5-X:nodwarf5",
				"goos":             "linux",
				"goarch":           "amd64",
				"build_date_epoch": 1790000000,
			},
		}
		encoded, err := json.Marshal(payload)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(t.TempDir(), "spec.json")
		if err := os.WriteFile(path, encoded, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := readSpec(path); err != nil {
			t.Fatalf("version %s with exact build metadata rejected: %v", productVersion, err)
		}
	}
}
