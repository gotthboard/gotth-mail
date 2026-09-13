package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"forgejo/gotthboard/gotth-mail/internal/api"
	"forgejo/gotthboard/gotth-mail/internal/authn"
)

func TestConfigureOIDCFromEnvDiscoversProvider(t *testing.T) {
	var base string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/application/o/gotth-mail/.well-known/openid-configuration":
			_ = json.NewEncoder(w).Encode(authn.DiscoveryDocument{Issuer: base + "/application/o/gotth-mail/", AuthorizationEndpoint: base + "/application/o/authorize/", TokenEndpoint: base + "/application/o/token/", JWKSURI: base + "/application/o/gotth-mail/jwks/", ResponseTypes: []string{"code"}, IDTokenAlgs: []string{"RS256"}})
		case "/application/o/gotth-mail/jwks/":
			_ = json.NewEncoder(w).Encode(authn.JWKS{Keys: []authn.JWK{{Kty: "RSA", Kid: "kid", Alg: "RS256", Use: "sig", N: "AQ", E: "AQAB"}}})
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
	server := api.Server{}
	if err := configureOIDCFromEnv(context.Background(), &server, srv.Client()); err != nil {
		t.Fatal(err)
	}
	if server.OIDCConfig.TokenEndpoint != base+"/application/o/token/" || server.OIDCAuthorizeEndpoint == "" || len(server.OIDCJWKS.Keys) != 1 || server.OIDCStore == nil || server.OIDCExchanger == nil {
		t.Fatalf("server=%#v", server)
	}
}

func TestConfigureOIDCFromEnvRequiresAllFieldsTogether(t *testing.T) {
	t.Setenv("GOTTH_MAIL_AUTHENTIK_ISSUER", "https://auth.example.test/application/o/gotth-mail/")
	if err := configureOIDCFromEnv(context.Background(), &api.Server{}, http.DefaultClient); err == nil {
		t.Fatal("accepted partial OIDC env")
	}
}
