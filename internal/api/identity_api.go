package api

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"forgejo/gotthboard/gotth-mail/internal/audit"
	"forgejo/gotthboard/gotth-mail/internal/identity"
)

func writeAPIAudit(w audit.Writer, r *http.Request, action, resource, result, code string) {
	if w == nil {
		return
	}
	_ = w.Write(r.Context(), audit.Event{Actor: audit.ActorRef{Type: "api", ID: r.RemoteAddr}, Action: action, Resource: audit.ResourceRef{Type: "identity", ID: resource}, Result: result, ErrorCode: code, CorrelationID: r.Header.Get("X-Correlation-ID")})
}

func (s *Server) identityService(auditLog *audit.MemoryWriter) *identity.Service {
	ids := s.Identity
	if ids == nil {
		var domains []string
		for name := range s.Daemon.Domains {
			domains = append(domains, name)
		}
		ids = identity.NewService(domains...)
	}
	if ids.Daemon == nil {
		ids.BindDaemon(&s.Daemon)
	}
	if ids.Authorizer == nil {
		ids.Authorizer = s.authorizer()
	}
	if ids.Audit == nil {
		ids.Audit = auditLog
	}
	return ids
}

func (s Server) registerIdentityAPI(mux *http.ServeMux, auditLog *audit.MemoryWriter, ids *identity.Service) {
	mux.HandleFunc("/api/v1/mailboxes/", func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimPrefix(r.URL.Path, "/api/v1/mailboxes/")
		parts := strings.Split(path, "/")
		if len(parts) < 2 || parts[1] != "app-passwords" {
			http.NotFound(w, r)
			return
		}
		mailboxID := parts[0]
		actor, err := ids.AuthenticateBearer(r.Header.Get("Authorization"), "api_token")
		if err != nil {
			writeAPIAudit(auditLog, r, "app_password.auth", mailboxID, "denied", err.Error())
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}
		switch {
		case len(parts) == 2 && r.Method == http.MethodGet:
			apps, err := ids.ListAppPasswordsForActor(r.Context(), actor, mailboxID)
			if err != nil {
				http.Error(w, err.Error(), http.StatusForbidden)
				return
			}
			writeJSON(w, apps)
		case len(parts) == 2 && r.Method == http.MethodPost:
			var in struct {
				Label string `json:"label"`
			}
			if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&in); err != nil {
				writeAPIAudit(auditLog, r, "app_password.create", mailboxID, "failure", "bad_request")
				http.Error(w, "bad app password request", http.StatusBadRequest)
				return
			}
			created, err := ids.CreateAppPassword(r.Context(), actor, mailboxID, in.Label)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			writeJSON(w, created)
		case len(parts) == 3 && r.Method == http.MethodDelete:
			if err := ids.RevokeAppPassword(r.Context(), actor, mailboxID, parts[2]); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			writeJSON(w, map[string]bool{"revoked": true})
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	})
}
