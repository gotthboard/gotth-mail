package identityruntime

import (
	"crypto/sha256"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestNormalizeIssuerAndScope(t *testing.T) {
	for raw, want := range map[string]string{"": "", "  ": "", " https://AUTH.example/a/// ": "https://AUTH.example/a/", "/": "/"} {
		if got := NormalizeIssuer(raw); got != want {
			t.Fatalf("normalize %q=%q want %q", raw, got, want)
		}
	}
	for _, actor := range []string{"stable-actor", "rotated-secret-same-actor", ""} {
		sum := sha256.Sum256([]byte("gotth-mail/scim-scope/v1\x00" + actor))
		want := base64.RawURLEncoding.EncodeToString(sum[:])
		if Scope(actor) != want {
			t.Fatal("scope derivation drift")
		}
	}
}

func TestLoadIssuerProtectedBoundedJSON(t *testing.T) {
	if got, err := LoadIssuer(""); err != nil || got != "" {
		t.Fatalf("absent %q %v", got, err)
	}
	valid := `{"GOTTH_MAIL_AUTHENTIK_ISSUER":" https://auth.example/application/o/gotth-mail/// "}`
	for _, tc := range []struct {
		name, body string
		mode       os.FileMode
		ok         bool
	}{
		{"valid", valid, 0600, true}, {"owner read", valid, 0400, true},
		{"empty", "", 0600, false}, {"missing", "{}", 0600, false}, {"null", "null", 0600, false},
		{"unknown", `{"other":"value"}`, 0600, false},
		{"duplicate", `{"GOTTH_MAIL_AUTHENTIK_ISSUER":"https://a/","GOTTH_MAIL_AUTHENTIK_ISSUER":"https://a/"}`, 0600, false},
		{"nonstring", `{"GOTTH_MAIL_AUTHENTIK_ISSUER":7}`, 0600, false},
		{"blank", `{"GOTTH_MAIL_AUTHENTIK_ISSUER":"  "}`, 0600, false},
		{"trailing", valid + "{}", 0600, false}, {"array", "[" + valid + "]", 0600, false},
		{"4095", valid + strings.Repeat(" ", 4095-len(valid)), 0600, true},
		{"4096", valid + strings.Repeat(" ", 4096-len(valid)), 0600, true},
		{"4097", valid + strings.Repeat(" ", 4097-len(valid)), 0600, false},
		{"oversized", strings.Repeat("x", 8192), 0600, false},
		{"group write", valid, 0620, false}, {"world write", valid, 0602, false}, {"world readable", valid, 0604, false}, {"unadmitted group reader", valid, 0640, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "runtime.json")
			if err := os.WriteFile(path, []byte(tc.body), tc.mode); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(path, tc.mode); err != nil {
				t.Fatal(err)
			}
			got, err := LoadIssuer(path)
			if tc.ok {
				if err != nil || got != "https://auth.example/application/o/gotth-mail/" {
					t.Fatalf("issuer=%q err=%v", got, err)
				}
			} else if err == nil || got != "" {
				t.Fatalf("unsafe input accepted %q %v", got, err)
			}
		})
	}
	t.Run("symlink", func(t *testing.T) {
		dir := t.TempDir()
		target := filepath.Join(dir, "target")
		link := filepath.Join(dir, "link")
		_ = os.WriteFile(target, []byte(valid), 0600)
		if err := os.Symlink(target, link); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadIssuer(link); err == nil {
			t.Fatal("symlink accepted")
		}
	})
	t.Run("directory", func(t *testing.T) {
		if _, err := LoadIssuer(t.TempDir()); err == nil {
			t.Fatal("directory accepted")
		}
	})
	t.Run("fifo", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "pipe")
		if err := syscall.Mkfifo(path, 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadIssuer(path); err == nil {
			t.Fatal("FIFO accepted")
		}
	})
	t.Run("missing", func(t *testing.T) {
		if _, err := LoadIssuer(filepath.Join(t.TempDir(), "missing")); err == nil {
			t.Fatal("missing configured file accepted")
		}
	})
}

func TestServiceIssuerEquality(t *testing.T) {
	path := filepath.Join(t.TempDir(), "runtime")
	if err := os.WriteFile(path, []byte(`{"GOTTH_MAIL_AUTHENTIK_ISSUER":"https://auth.example/"}`), 0600); err != nil {
		t.Fatal(err)
	}
	if got, err := ServiceIssuer(path, " https://auth.example/// "); err != nil || got != "https://auth.example/" {
		t.Fatalf("equal %q %v", got, err)
	}
	for _, env := range []string{"", "https://wrong.example/"} {
		if got, err := ServiceIssuer(path, env); err == nil || got != "" {
			t.Fatal("mismatch accepted")
		}
	}
	if got, err := ServiceIssuer("", "https://auth.example/"); err != nil || got != "" {
		t.Fatal("env-only granted Group authority")
	}
}
