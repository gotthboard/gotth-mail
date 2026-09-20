package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"forgejo/gotthboard/gotth-mail/internal/api"
)

func TestConfigureFrontAuthFromEnv(t *testing.T) {
	path := t.TempDir() + "/front-token"
	if err := os.WriteFile(path, []byte("0123456789abcdef0123456789abcdef\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GOTTH_MAIL_FRONT_AUTH_TOKEN_FILE", path)
	server := api.Server{}
	if err := configureFrontAuthFromEnv(&server); err != nil {
		t.Fatal(err)
	}
	if server.FrontAuth == nil {
		t.Fatal("front auth handler not configured")
	}
	r := httptest.NewRequest(http.MethodGet, "/internal/v1/front/auth", nil)
	r.Header.Set("X-GOTTH-Mail-Front-Token", "wrong-wrong-wrong-wrong-wrong-wrong")
	w := httptest.NewRecorder()
	runtimeMux(server).ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatalf("status=%d", w.Code)
	}
}

func TestConfigureFrontAuthRequiresPrivateFile(t *testing.T) {
	path := t.TempDir() + "/front-token"
	if err := os.WriteFile(path, []byte("0123456789abcdef0123456789abcdef"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GOTTH_MAIL_FRONT_AUTH_TOKEN_FILE", path)
	if err := configureFrontAuthFromEnv(&api.Server{}); err == nil {
		t.Fatal("public front-auth token file accepted")
	}
}
