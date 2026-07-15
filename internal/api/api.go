package api

import (
	"encoding/json"
	"net/http"

	"forgejo/linus/gophermailforge/internal/authz"
)

type Server struct{ Authz authz.Authorizer }

func (s Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200); _, _ = w.Write([]byte("ok\n")) })
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200); _, _ = w.Write([]byte("ready\n")) })
	mux.HandleFunc("/api/v1/status", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"status": "v0-foundation", "mail_stack_complete": false})
	})
	mux.HandleFunc("/api/v1/authz/explain", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			w.WriteHeader(405)
			return
		}
		ex, _ := s.Authz.Explain(r.Context(), authz.Actor{Type: "local_admin", ID: "local"}, authz.Action("status:read"), authz.Resource{Type: "system", ID: "self"})
		json.NewEncoder(w).Encode(ex)
	})
	return mux
}
