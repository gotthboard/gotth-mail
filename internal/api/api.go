package api

import (
	"encoding/json"
	"net/http"
	"strings"

	"forgejo/gotthboard/gotth-mail/internal/apply"
	"forgejo/gotthboard/gotth-mail/internal/audit"
	"forgejo/gotthboard/gotth-mail/internal/authz"
	"forgejo/gotthboard/gotth-mail/internal/config"
	"forgejo/gotthboard/gotth-mail/internal/daemon"
	"forgejo/gotthboard/gotth-mail/internal/diag"
	"forgejo/gotthboard/gotth-mail/internal/ops"
	"forgejo/gotthboard/gotth-mail/internal/plugin"
	"forgejo/gotthboard/gotth-mail/internal/render"
)

type Server struct {
	Authz     authz.Authorizer
	Config    config.Config
	Audit     *audit.MemoryWriter
	Plugins   plugin.Registry
	Applied   *render.Set
	Daemon    daemon.Service
	Queue     *ops.Queue
	DNSChecks []diag.DNSRecordCheck
	CertCheck diag.CertCheck
	WebmailOK bool
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
	queue := s.Queue
	if queue == nil {
		queue = &ops.Queue{}
	}
	mux.HandleFunc("/api/v1/doctor", func(w http.ResponseWriter, r *http.Request) {
		if !method(w, r, "GET") {
			return
		}
		cert := s.CertCheck
		if cert.Status == "" {
			cert = diag.CertCheck{Status: diag.CertUnknown, Reason: "not_configured"}
		}
		webmailOK := s.WebmailOK
		writeJSON(w, ops.Doctor(r.Context(), ops.DoctorInput{ConfigOK: true, DatabaseOK: true, AuthentikOK: true, WebmailOK: webmailOK, Daemon: s.Daemon, DNSChecks: s.DNSChecks, CertCheck: cert, PluginRegistry: s.Plugins, PluginToken: r.Header.Get("X-GOTTH-Mail-Plugin-Token"), CorrelationID: r.Header.Get("X-Correlation-ID")}))
	})
	mux.HandleFunc("/api/v1/debug/lookup", func(w http.ResponseWriter, r *http.Request) {
		if !method(w, r, "GET") {
			return
		}
		writeJSON(w, ops.DebugLookup(s.Daemon, r.URL.Query().Get("kind"), r.URL.Query().Get("value"), r.Header.Get("X-Correlation-ID")))
	})
	mux.HandleFunc("/api/v1/queue/summary", func(w http.ResponseWriter, r *http.Request) {
		if !method(w, r, "GET") {
			return
		}
		writeJSON(w, queue.Summary)
	})
	mux.HandleFunc("/api/v1/queue/deferred", func(w http.ResponseWriter, r *http.Request) {
		if !method(w, r, "GET") {
			return
		}
		writeJSON(w, queue.Summary.Deferred)
	})
	mux.HandleFunc("/api/v1/queue/flush", func(w http.ResponseWriter, r *http.Request) {
		if !method(w, r, "POST") {
			return
		}
		if err := queue.Flush(r.Context(), auditLog, actor(r), r.URL.Query().Get("confirm")); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		writeJSON(w, map[string]any{"flushed": true})
	})
	mux.HandleFunc("/api/v1/queue/retry", func(w http.ResponseWriter, r *http.Request) {
		if !method(w, r, "POST") {
			return
		}
		if err := queue.Retry(r.Context(), auditLog, actor(r), r.URL.Query().Get("confirm")); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		writeJSON(w, map[string]any{"retried": true})
	})
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
