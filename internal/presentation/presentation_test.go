package presentation

import (
	"crypto/sha256"
	"fmt"
	"os"
	"strings"
	"testing"
)

func TestSharedPresentationIdentity(t *testing.T) {
	for _, tc := range []struct{ got, want string }{
		{LightColors, "--bg:#f4f6f9;--surface:#fff;--surface-2:#edf2f7;--text:#172033;--muted:#596579;--line:#c6cfdb;--accent:#175ea8;--accent-2:#0d4d8d;--focus:#ffb000;--danger:#a3212b;"},
		{DarkColors, "--bg:#111722;--surface:#182230;--surface-2:#202d3d;--text:#eef4fb;--muted:#b0bfd0;--line:#405064;--accent:#69adf0;--accent-2:#8bc2f5;--focus:#ffd166;--danger:#ff8e96;"},
	} {
		if tc.got != tc.want || strings.ContainsAny(tc.got, "{}") {
			t.Fatal("shared scalar identity drift")
		}
	}
	if got := fmt.Sprintf("%x", sha256.Sum256([]byte(HTMX()))); got != "71ea67185bfa8c98c39d31717c6fce5d852370fcdfd129db4543774d3145c0de" {
		t.Fatal("HTMX identity drift", got)
	}
	license, err := os.ReadFile("assets/htmx-LICENSE")
	if err != nil {
		t.Fatal(err)
	}
	if fmt.Sprintf("%x", sha256.Sum256(license)) != "d3d2456f76414f2456104660ebd65aff1c04cd7966b942bdabd63f3cdb316a38" {
		t.Fatal("license identity drift")
	}
}
