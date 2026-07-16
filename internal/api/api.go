package api

import (
	"encoding/json"
	"net/http"
	"strings"

	"forgejo/linus/gophermailforge/internal/apply"
	"forgejo/linus/gophermailforge/internal/audit"
	"forgejo/linus/gophermailforge/internal/authz"
	"forgejo/linus/gophermailforge/internal/config"
	"forgejo/linus/gophermailforge/internal/daemon"
	"forgejo/linus/gophermailforge/internal/plugin"
	"forgejo/linus/gophermailforge/internal/render"
)

type Server struct {
	Authz   authz.Authorizer
	Config  config.Config
	Audit   *audit.MemoryWriter
	Plugins plugin.Registry
	Applied *render.Set
	Daemon  daemon.Service
}

func (s Server) Handler() http.Handler {
	mux := http.NewServeMux()
	auditLog := s.Audit
	if auditLog == nil {
		auditLog = &audit.MemoryWriter{}
	}
	applied := s.Applied
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		if method(w, r, "GET") {
			writeText(w, "ok\n")
		}
	})
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) {
		if method(w, r, "GET") {
			writeText(w, "ready\n")
		}
	})
	mux.HandleFunc("/api/v1/status", func(w http.ResponseWriter, r *http.Request) {
		if !method(w, r, "GET") {
			return
		}
		writeJSON(w, map[string]any{"status": "v0-foundation", "mail_stack_complete": false})
	})
	mux.HandleFunc("/api/v1/authz/explain", func(w http.ResponseWriter, r *http.Request) {
		if !method(w, r, "POST") {
			return
		}
		ex, _ := s.authorizer().Explain(r.Context(), authz.Actor{Type: "local_admin", ID: "local"}, authz.Action("status:read"), authz.Resource{Type: "system", ID: "self"})
		writeJSON(w, ex)
	})
	mux.HandleFunc("/api/v1/config/effective", func(w http.ResponseWriter, r *http.Request) {
		if !method(w, r, "GET") {
			return
		}
		writeJSON(w, s.Config)
	})
	mux.HandleFunc("/api/v1/config/render", func(w http.ResponseWriter, r *http.Request) {
		if !method(w, r, "POST") {
			return
		}
		staged := render.Render(s.Config)
		_ = auditLog.Write(r.Context(), audit.Event{Actor: actor(r), Source: &audit.RequestSource{IP: r.RemoteAddr, UserAgent: r.UserAgent()}, Action: "config.render", Resource: audit.ResourceRef{Type: "generated_config_set", ID: staged.ID}, Result: "success"})
		writeJSON(w, map[string]any{"id": staged.ID, "files": len(staged.Files)})
	})
	mux.HandleFunc("/api/v1/config/render/", func(w http.ResponseWriter, r *http.Request) {
		parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/v1/config/render/"), "/")
		if len(parts) != 2 {
			http.NotFound(w, r)
			return
		}
		id, action := parts[0], parts[1]
		staged := render.Render(s.Config)
		if id != staged.ID {
			http.Error(w, "unknown staged render", http.StatusNotFound)
			return
		}
		switch action {
		case "diff":
			if !method(w, r, "GET") {
				return
			}
			current := render.Set{}
			if applied != nil {
				current = *applied
			}
			writeJSON(w, map[string]any{"id": staged.ID, "diff": render.Diff(current, staged)})
		case "apply":
			if !method(w, r, "POST") {
				return
			}
			confirm := r.URL.Query().Get("confirm")
			g := apply.Gate{Audit: auditLog, Applied: applied}
			if err := g.Apply(r.Context(), actor(r), staged, confirm); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			applied = g.Applied
			writeJSON(w, map[string]any{"applied": staged.ID})
		default:
			http.NotFound(w, r)
		}
	})
	mux.HandleFunc("/api/v1/audit/events", func(w http.ResponseWriter, r *http.Request) {
		if !method(w, r, "GET") {
			return
		}
		writeJSON(w, auditLog.Events)
	})
	mux.HandleFunc("/api/v1/plugins", func(w http.ResponseWriter, r *http.Request) {
		if !method(w, r, "GET") {
			return
		}
		writeJSON(w, s.Plugins.Plugins)
	})
	s.Daemon.Register(mux)
	mux.HandleFunc("/api/v1/plugins/", func(w http.ResponseWriter, r *http.Request) {
		if !method(w, r, "GET") {
			return
		}
		name := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/api/v1/plugins/"), "/health")
		p, ok := s.Plugins.Plugins[name]
		if !ok {
			http.NotFound(w, r)
			return
		}
		writeJSON(w, map[string]any{"name": name, "enabled": p.Enabled, "healthy": p.Enabled})
	})
	return mux
}

func (s Server) authorizer() authz.Authorizer {
	if s.Authz != nil {
		return s.Authz
	}
	return authz.StaticAuthorizer{}
}
func actor(r *http.Request) audit.ActorRef { return audit.ActorRef{Type: "local_admin", ID: "local"} }
func method(w http.ResponseWriter, r *http.Request, want string) bool {
	if r.Method != want {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return false
	}
	return true
}
func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("content-type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
func writeText(w http.ResponseWriter, s string) bool { _, _ = w.Write([]byte(s)); return true }
