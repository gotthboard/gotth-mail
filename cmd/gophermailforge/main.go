package main

import (
	"log"
	"net/http"
	"os"

	"forgejo/linus/gophermailforge/internal/api"
	"forgejo/linus/gophermailforge/internal/authz"
	"forgejo/linus/gophermailforge/internal/daemon"
	"forgejo/linus/gophermailforge/internal/httpui"
	"forgejo/linus/gophermailforge/internal/plugin"
)

func main() {
	mux := http.NewServeMux()
	server := api.Server{Authz: authz.StaticAuthorizer{}}
	if os.Getenv("GMF_REFERENCE_FIXTURE") == "1" {
		server = referenceServer()
	}
	mux.Handle("/api/", server.Handler())
	mux.Handle("/internal/", server.Handler())
	mux.Handle("/healthz", server.Handler())
	mux.Handle("/readyz", server.Handler())
	mux.Handle("/", httpui.Handler())
	addr := os.Getenv("GMF_LISTEN")
	if addr == "" {
		addr = ":8080"
	}
	log.Fatal(http.ListenAndServe(addr, mux))
}

func referenceServer() api.Server {
	verifier := daemon.MakeDjangoPBKDF2SHA256("smoke-secret", "smokesalt", 1200)
	return api.Server{
		Authz: authz.StaticAuthorizer{},
		Daemon: daemon.Service{
			Domains: map[string]daemon.Domain{"example.test": {Name: "example.test", Enabled: true, Transport: "virtual:", DKIMSelector: "mail", DKIMPrivateKeyPath: "/run/rspamd/dkim/example.test.mail.key"}},
			Mailboxes: map[string]daemon.Mailbox{
				"smoke@example.test":      {Address: "smoke@example.test", Enabled: true, Home: "/mail/example.test/smoke", UID: 5000, GID: 5000, QuotaBytes: 1073741824, Verifier: verifier},
				"postmaster@example.test": {Address: "postmaster@example.test", Enabled: true, Home: "/mail/example.test/postmaster", UID: 5000, GID: 5000, QuotaBytes: 1073741824, Verifier: verifier},
			},
			Aliases: map[string]daemon.Alias{"alias@example.test": {Address: "alias@example.test", Enabled: true, Targets: []string{"smoke@example.test"}}},
		},
		Plugins: plugin.FirstMechanismPlugins("dev-plugin-token"),
	}
}
