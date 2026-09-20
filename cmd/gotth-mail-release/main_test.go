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
	root := t.TempDir()
	for name := range requiredConfiguration {
		path := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("content:"+name+"\n"), 0o440); err != nil {
			t.Fatal(err)
		}
	}
	spec := releaseSpec{
		ProductVersion: "1.0.0-alpha.1", TagObject: strings.Repeat("a", 40),
		SourceCommit: strings.Repeat("b", 40), ForgejoRefCommit: strings.Repeat("b", 40), GitHubRefCommit: strings.Repeat("b", 40),
		Images: map[string]string{}, Schema: schemaRange{Minimum: 17, Current: 17, Maximum: 17},
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
	if err := os.WriteFile(filepath.Join(root, "unknown"), []byte("x"), 0o440); err != nil {
		t.Fatal(err)
	}
	if _, _, err := readConfiguration(root); err == nil {
		t.Fatal("unknown configuration member accepted")
	}
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
