package contract_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	gotthoidc "github.com/gotthboard/gotth-oidc/pkg/oidc"
	gotthscim "github.com/gotthboard/gotth-scim/pkg/scim"
)

func TestGOTTHOIDCConsumerContract(t *testing.T) {
	t.Parallel()
	var issuer string
	provider := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/application/o/gotth-mail/.well-known/openid-configuration" {
			http.NotFound(writer, request)
			return
		}
		writer.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(writer).Encode(map[string]any{
			"issuer":                                issuer,
			"authorization_endpoint":                strings.TrimSuffix(issuer, "/") + "/authorize",
			"token_endpoint":                        strings.TrimSuffix(issuer, "/") + "/token",
			"jwks_uri":                              strings.TrimSuffix(issuer, "/") + "/jwks",
			"response_types_supported":              []string{"code"},
			"subject_types_supported":               []string{"public"},
			"id_token_signing_alg_values_supported": []string{"RS256"},
			"token_endpoint_auth_methods_supported": []string{"client_secret_basic"},
		})
	}))
	defer provider.Close()
	issuer = provider.URL + "/application/o/gotth-mail/"

	client, err := gotthoidc.New(context.Background(), gotthoidc.Config{
		IssuerURL: issuer, ClientID: "gotth-mail", ClientSecret: "test-only-secret",
		RedirectURL: "http://127.0.0.1:18080/api/v1/oidc/callback",
		Transport:   provider.Client().Transport, AllowInsecureLoopback: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	authorization, err := client.Begin()
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := url.Parse(authorization.URL)
	if err != nil {
		t.Fatal(err)
	}
	query := parsed.Query()
	for key, want := range map[string]string{"response_type": "code", "client_id": "gotth-mail", "code_challenge_method": "S256"} {
		if got := query.Get(key); got != want {
			t.Errorf("authorization %s = %q, want %q", key, got, want)
		}
	}
	if query.Get("state") == "" || query.Get("nonce") == "" || query.Get("code_challenge") == "" || authorization.Attempt.ContextCiphertext == "" {
		t.Fatal("OIDC authorization omitted protected state, nonce, PKCE, or attempt context")
	}
}

func TestGOTTHSCIMConsumerContract(t *testing.T) {
	t.Parallel()
	registry, err := gotthscim.NewRegistry(gotthscim.DefaultDefinitions())
	if err != nil {
		t.Fatal(err)
	}
	server, err := gotthscim.NewServer(gotthscim.ServerConfig{
		Store: gotthscim.NewMemoryStore(), Registry: registry,
		ExternalURL: "https://mail.example.test/scim/v2",
		ResolveScope: func(request *http.Request) (string, error) {
			if request.Header.Get("Authorization") != "Bearer test-only-token" {
				return "", fmt.Errorf("unauthorized")
			}
			return "authentik:test", nil
		},
		AuthenticationSchemes: []gotthscim.AuthenticationScheme{{Type: "oauthbearertoken", Name: "Bearer", Description: "GOTTH Mail provisioning token"}},
	})
	if err != nil {
		t.Fatal(err)
	}

	create := httptest.NewRequest(http.MethodPost, "https://mail.example.test/scim/v2/Users", strings.NewReader(`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"user@example.test","displayName":"User","active":true}`))
	create.Header.Set("Authorization", "Bearer test-only-token")
	create.Header.Set("Content-Type", "application/scim+json")
	created := httptest.NewRecorder()
	server.ServeHTTP(created, create)
	if created.Code != http.StatusCreated {
		t.Fatalf("SCIM create status = %d body=%s", created.Code, created.Body.String())
	}
	var resource map[string]any
	if err := json.Unmarshal(created.Body.Bytes(), &resource); err != nil {
		t.Fatal(err)
	}
	id, _ := resource["id"].(string)
	if id == "" || id == "user@example.test" {
		t.Fatalf("SCIM resource ID = %q, want opaque persistent ID", id)
	}

	read := httptest.NewRequest(http.MethodGet, "https://mail.example.test/scim/v2/Users/"+url.PathEscape(id), nil)
	read.Header.Set("Authorization", "Bearer test-only-token")
	got := httptest.NewRecorder()
	server.ServeHTTP(got, read)
	if got.Code != http.StatusOK || !strings.Contains(got.Body.String(), `"userName":"user@example.test"`) {
		t.Fatalf("SCIM read status = %d body=%s", got.Code, got.Body.String())
	}
}
