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
	"forgejo/gotthboard/gotth-mail/internal/audit"
	"forgejo/gotthboard/gotth-mail/internal/authn"
	"forgejo/gotthboard/gotth-mail/internal/authz"
	"forgejo/gotthboard/gotth-mail/internal/identity"
	"forgejo/gotthboard/gotth-mail/internal/outboundpolicy"
	"forgejo/gotthboard/gotth-mail/internal/store"
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

func TestConfigureSCIMFromEnvRequiresDurabilityAndBuildsHandler(t *testing.T) {
	t.Setenv("GOTTH_MAIL_SCIM_EXTERNAL_URL", "https://mail.example.test/scim/v2")
	if err := configureSCIMFromEnv(&api.Server{}); err == nil {
		t.Fatal("SCIM accepted missing durable database")
	}
	db := testpg.DB(t, store.MigrateSQL)
	ids, err := identity.NewSQLService(context.Background(), db, "example.test")
	if err != nil {
		t.Fatal(err)
	}
	if err := ids.AddToken("scim-runtime", "scim_client", "runtime-secret"); err != nil {
		t.Fatal(err)
	}
	server := api.Server{AuditDB: db, Identity: ids, Authz: authz.StaticAuthorizer{}}
	if err := configureSCIMFromEnv(&server); err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "/scim/v2/ServiceProviderConfig", nil)
	request.Header.Set("Authorization", "Bearer runtime-secret")
	response := httptest.NewRecorder()
	server.SCIM.ServeHTTP(response, request)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "ServiceProviderConfig") {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestRuntimeMuxRoutesSCIMToAPIServer(t *testing.T) {
	server := api.Server{SCIM: http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusTeapot)
	})}
	response := httptest.NewRecorder()
	runtimeMux(server).ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/scim/v2/Users", nil))
	if response.Code != http.StatusTeapot {
		t.Fatalf("SCIM route escaped API server: status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestRuntimeMuxSharesConfiguredIdentityServiceWithUI(t *testing.T) {
	ids := identity.NewService("example.test")
	if _, err := ids.CreateOrReplaceUser(context.Background(), authz.Actor{Type: "local_admin", ID: "seed"}, identity.Mailbox{Email: "private@example.test", Active: true}, "mail-password"); err != nil {
		t.Fatal(err)
	}
	h := runtimeMux(api.Server{Identity: ids, Authz: authz.StaticAuthorizer{}})
	response := httptest.NewRecorder()
	h.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/", nil))
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "Browser self-service is unavailable") {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	if strings.Contains(response.Body.String(), "private@example.test") {
		t.Fatal("runtime UI leaked configured identity state before subject binding")
	}
	if ids.Daemon == nil || ids.Authorizer == nil || ids.Audit == nil {
		t.Fatalf("runtime API did not initialize the shared configured identity service: %#v", ids)
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
	if server.AuditDB == nil || server.OIDCStore == nil || server.Identity == nil || server.Daemon.OutboundPolicy == nil || server.Daemon.OutboundAdmission == nil {
		t.Fatalf("database services not wired: %#v", server)
	}
	if _, ok := server.Identity.Audit.(audit.SQLWriter); !ok {
		t.Fatalf("configured identity/passdb audit is not durable: %T", server.Identity.Audit)
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

func TestConfigurePostfixHelperRequiresCompleteDurableConfiguration(t *testing.T) {
	t.Setenv("GOTTH_MAIL_POSTFIX_HELPER_URL", "http://postfix:10026")
	t.Setenv("GOTTH_MAIL_POSTFIX_HELPER_TOKEN", "0123456789abcdef0123456789abcdef")
	if err := configurePostfixHelperFromEnv(&api.Server{}); err == nil {
		t.Fatal("Postfix helper accepted missing database wiring")
	}
	db := testpg.DB(t, store.MigrateSQL)
	server := api.Server{AuditDB: db}
	server.Daemon.OutboundAdmission = &outboundpolicy.QueueAdmissionService{DB: db}
	if err := configurePostfixHelperFromEnv(&server); err != nil {
		t.Fatal(err)
	}
	if server.Daemon.OutboundReconciler == nil {
		t.Fatal("Postfix queue reconciler was not wired")
	}
}

func TestConfigureDatabaseSeedsExplicitReferencePolicyFixture(t *testing.T) {
	seed := testpg.DB(t, nil)
	var port int
	if err := seed.QueryRow(`SELECT inet_server_port()`).Scan(&port); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GOTTH_MAIL_DATABASE_URL", fmt.Sprintf("postgres://gotth_mail@127.0.0.1:%d/gotth_mail?sslmode=disable", port))
	t.Setenv("GOTTH_MAIL_REFERENCE_FIXTURE", "1")
	server := api.Server{}
	db, err := configureDatabaseFromEnv(context.Background(), &server)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var scope string
	var revision int
	if err := db.QueryRow(`SELECT outbound_scope,outbound_policy_revision FROM domains WHERE name='example.test'`).Scan(&scope, &revision); err != nil {
		t.Fatal(err)
	}
	if scope != "same_domain_only" || revision != 2 {
		t.Fatalf("scope=%q revision=%d", scope, revision)
	}
}
