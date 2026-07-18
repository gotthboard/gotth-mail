package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"forgejo/linus/gophermailforge/internal/api"
	"forgejo/linus/gophermailforge/internal/authn"
)

func TestConfigureOIDCFromEnvDiscoversProvider(t *testing.T) {
	var base string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/application/o/gophermailforge/.well-known/openid-configuration":
			_ = json.NewEncoder(w).Encode(authn.DiscoveryDocument{Issuer: base + "/application/o/gophermailforge/", AuthorizationEndpoint: base + "/application/o/authorize/", TokenEndpoint: base + "/application/o/token/", JWKSURI: base + "/application/o/gophermailforge/jwks/", ResponseTypes: []string{"code"}, IDTokenAlgs: []string{"RS256"}})
		case "/application/o/gophermailforge/jwks/":
			_ = json.NewEncoder(w).Encode(authn.JWKS{Keys: []authn.JWK{{Kty: "RSA", Kid: "kid", Alg: "RS256", Use: "sig", N: "AQ", E: "AQAB"}}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	base = srv.URL
	t.Setenv("GMF_AUTHENTIK_ISSUER", base+"/application/o/gophermailforge/")
	t.Setenv("GMF_AUTHENTIK_CLIENT_ID", "gmf")
	t.Setenv("GMF_AUTHENTIK_CLIENT_SECRET", "secret")
	t.Setenv("GMF_AUTHENTIK_REDIRECT_URI", "http://127.0.0.1:18080/api/v1/oidc/callback")
	server := api.Server{}
	if err := configureOIDCFromEnv(context.Background(), &server, srv.Client()); err != nil {
		t.Fatal(err)
	}
	if server.OIDCConfig.TokenEndpoint != base+"/application/o/token/" || server.OIDCAuthorizeEndpoint == "" || len(server.OIDCJWKS.Keys) != 1 || server.OIDCStore == nil || server.OIDCExchanger == nil {
		t.Fatalf("server=%#v", server)
	}
}

func TestConfigureOIDCFromEnvRequiresAllFieldsTogether(t *testing.T) {
	t.Setenv("GMF_AUTHENTIK_ISSUER", "https://auth.example.test/application/o/gmf/")
	if err := configureOIDCFromEnv(context.Background(), &api.Server{}, http.DefaultClient); err == nil {
		t.Fatal("accepted partial OIDC env")
	}
}
