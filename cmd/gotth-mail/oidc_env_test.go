package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"forgejo/gotthboard/gotth-mail/internal/api"
	"forgejo/gotthboard/gotth-mail/internal/authn"
	"forgejo/gotthboard/gotth-mail/internal/testpg"
)

func TestConfigureOIDCFromEnvDiscoversProvider(t *testing.T) {
	var base string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/application/o/gotth-mail/.well-known/openid-configuration":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"issuer":                                base + "/application/o/gotth-mail/",
				"authorization_endpoint":                base + "/application/o/authorize/",
				"token_endpoint":                        base + "/application/o/token/",
				"jwks_uri":                              base + "/application/o/gotth-mail/jwks/",
				"response_types_supported":              []string{"code"},
				"subject_types_supported":               []string{"public"},
				"id_token_signing_alg_values_supported": []string{"RS256"},
				"token_endpoint_auth_methods_supported": []string{"client_secret_basic"},
				"code_challenge_methods_supported":      []string{"S256"},
			})
		case "/application/o/gotth-mail/jwks/":
			_ = json.NewEncoder(w).Encode(map[string]any{"keys": []any{}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	base = srv.URL
	t.Setenv("GOTTH_MAIL_AUTHENTIK_ISSUER", base+"/application/o/gotth-mail/")
	t.Setenv("GOTTH_MAIL_AUTHENTIK_CLIENT_ID", "gotth-mail")
	t.Setenv("GOTTH_MAIL_AUTHENTIK_CLIENT_SECRET", "secret")
	t.Setenv("GOTTH_MAIL_AUTHENTIK_REDIRECT_URI", "http://127.0.0.1:18080/api/v1/oidc/callback")
	server := api.Server{OIDCStore: authn.NewStore()}
	if err := configureOIDCFromEnv(context.Background(), &server, srv.Client()); err != nil {
		t.Fatal(err)
	}
	if server.OIDCClient == nil || server.OIDCStore == nil || server.OIDCRedirectURI != "http://127.0.0.1:18080/api/v1/oidc/callback" {
		t.Fatalf("server=%#v", server)
	}
}

func TestConfigureOIDCFromEnvRequiresAllFieldsTogether(t *testing.T) {
	t.Setenv("GOTTH_MAIL_AUTHENTIK_ISSUER", "https://auth.example.test/application/o/gotth-mail/")
	if err := configureOIDCFromEnv(context.Background(), &api.Server{}, http.DefaultClient); err == nil {
		t.Fatal("accepted partial OIDC env")
	}
}

func TestConfigureOIDCFromEnvRequiresDurableStore(t *testing.T) {
	t.Setenv("GOTTH_MAIL_AUTHENTIK_ISSUER", "https://auth.example.test/application/o/gotth-mail/")
	t.Setenv("GOTTH_MAIL_AUTHENTIK_CLIENT_ID", "gotth-mail")
	t.Setenv("GOTTH_MAIL_AUTHENTIK_REDIRECT_URI", "https://mail.example.test/api/v1/oidc/callback")
	if err := configureOIDCFromEnv(context.Background(), &api.Server{}, http.DefaultClient); err == nil {
		t.Fatal("OIDC accepted volatile state storage")
	}
}

func TestConfigureDatabaseFromEnvRejectsAmbiguousSecretSource(t *testing.T) {
	t.Setenv("GOTTH_MAIL_DATABASE_URL", "postgres://direct")
	t.Setenv("GOTTH_MAIL_DATABASE_URL_FILE", "/run/secrets/database-url")
	if _, err := configureDatabaseFromEnv(context.Background(), &api.Server{}); err == nil {
		t.Fatal("database configuration accepted two secret sources")
	}
}

func TestSecretFromEnvOrFileReadsOneBoundedSource(t *testing.T) {
	path := t.TempDir() + "/secret"
	if err := os.WriteFile(path, []byte("from-file\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TEST_SECRET_FILE", path)
	got, err := secretFromEnvOrFile("TEST_SECRET", "TEST_SECRET_FILE")
	if err != nil || got != "from-file" {
		t.Fatalf("secret=%q err=%v", got, err)
	}
	t.Setenv("TEST_SECRET", "from-env")
	if _, err := secretFromEnvOrFile("TEST_SECRET", "TEST_SECRET_FILE"); err == nil {
		t.Fatal("secret helper accepted two sources")
	}
	t.Setenv("TEST_SECRET", "")
	oversized := t.TempDir() + "/oversized"
	if err := os.WriteFile(oversized, []byte(strings.Repeat("x", (64<<10)+1)), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TEST_SECRET_FILE", oversized)
	if _, err := secretFromEnvOrFile("TEST_SECRET", "TEST_SECRET_FILE"); err == nil {
		t.Fatal("oversized secret file accepted")
	}
}

func TestConfigureDatabaseFromEnvMigratesAndWiresDurableServices(t *testing.T) {
	seed := testpg.DB(t, nil)
	var port int
	if err := seed.QueryRow(`SELECT inet_server_port()`).Scan(&port); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GOTTH_MAIL_DATABASE_URL", fmt.Sprintf("postgres://gotth_mail@127.0.0.1:%d/gotth_mail?sslmode=disable", port))
	server := api.Server{}
	db, err := configureDatabaseFromEnv(context.Background(), &server)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if server.AuditDB == nil || server.OIDCStore == nil || server.Identity == nil {
		t.Fatalf("database services not wired: %#v", server)
	}
	if server.Identity.Daemon != nil {
		t.Fatal("database configuration bound identity to a daemon copy before handler construction")
	}
	_ = server.Handler()
	if server.Identity.Daemon == nil {
		t.Fatal("handler did not bind the durable identity service to its daemon state")
	}
	var migrations int
	if err := db.QueryRow(`SELECT count(*) FROM schema_migrations`).Scan(&migrations); err != nil {
		t.Fatal(err)
	}
	if migrations == 0 {
		t.Fatal("database migration ledger is empty")
	}
}
