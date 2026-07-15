package main

import (
	"log"
	"net/http"
	"os"

	"forgejo/linus/gophermailforge/internal/api"
	"forgejo/linus/gophermailforge/internal/authz"
	"forgejo/linus/gophermailforge/internal/httpui"
)

func main() {
	mux := http.NewServeMux()
	mux.Handle("/api/", api.Server{Authz: authz.StaticAuthorizer{}}.Handler())
	mux.Handle("/healthz", api.Server{Authz: authz.StaticAuthorizer{}}.Handler())
	mux.Handle("/readyz", api.Server{Authz: authz.StaticAuthorizer{}}.Handler())
	mux.Handle("/", httpui.Handler())
	addr := os.Getenv("GMF_LISTEN")
	if addr == "" {
		addr = ":8080"
	}
	log.Fatal(http.ListenAndServe(addr, mux))
}
