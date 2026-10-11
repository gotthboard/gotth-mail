package main

import (
	"forgejo/gotthboard/gotth-mail/internal/api"
	"forgejo/gotthboard/gotth-mail/internal/authn"
	"forgejo/gotthboard/gotth-mail/internal/identityruntime"
	"os"
)

// configureIdentityRuntimeFromEnv supplies immutable authority before handlers exist.
// Complexity: n<=4097 file bytes, e environment bytes, F filesystem work;
// time O(n+e+F), Omega(1), no uniform tight bound; auxiliary O(n+e), Omega(1),
// no uniform tight bound. Delegates only protected local loading, no network/SQL.
func configureIdentityRuntimeFromEnv(server *api.Server) error {
	issuer, err := identityruntime.ServiceIssuer(os.Getenv(identityruntime.ConfigFileEnv), os.Getenv(identityruntime.IssuerEnv))
	if err != nil {
		return err
	}
	server.CurrentIssuer = issuer
	if store, ok := server.OIDCStore.(authn.SQLStore); ok {
		store.CurrentIssuer = issuer
		server.OIDCStore = store
	}
	return nil
}
