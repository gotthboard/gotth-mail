package api

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"forgejo/gotthboard/gotth-mail/internal/audit"
	"forgejo/gotthboard/gotth-mail/internal/authn"
	"forgejo/gotthboard/gotth-mail/internal/authz"
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
		actor, browserSession, ok := s.identityRequestActor(w, r, ids)
		if !ok {
			writeAPIAudit(auditLog, r, "app_password.auth", mailboxID, "denied", "authentication_failed")
			return
		}
		if browserSession && (r.Method == http.MethodPost || r.Method == http.MethodDelete) && !s.validSessionCSRF(r) {
			writeAPIAudit(auditLog, r, "app_password.csrf", mailboxID, "denied", "csrf_failed")
			http.Error(w, "CSRF validation failed", http.StatusForbidden)
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

func (s Server) identityRequestActor(w http.ResponseWriter, r *http.Request, ids *identity.Service) (authz.Actor, bool, bool) {
	if r.Header.Get("Authorization") != "" {
		actor, err := ids.AuthenticateBearer(r.Header.Get("Authorization"), "api_token")
		if err != nil {
			http.Error(w, "identity authentication required", http.StatusUnauthorized)
			return authz.Actor{}, false, false
		}
		return actor, false, true
	}
	store, ok := s.OIDCStore.(authn.IdentitySessionStore)
	if !ok {
		http.Error(w, "identity authentication required", http.StatusUnauthorized)
		return authz.Actor{}, false, false
	}
	cookie, err := r.Cookie("gotth_mail_session")
	if err != nil || cookie.Value == "" {
		http.Error(w, "identity authentication required", http.StatusUnauthorized)
		return authz.Actor{}, false, false
	}
	bound, ok := store.BoundSession(r.Context(), cookie.Value, s.oidcNow())
	if !ok {
		http.Error(w, "identity session is invalid", http.StatusUnauthorized)
		return authz.Actor{}, false, false
	}
	return authz.Actor{Type: "oidc_subject", ID: bound.IdentityRefID, Mailbox: bound.Mailbox}, true, true
}

func (s Server) validSessionCSRF(r *http.Request) bool {
	store, ok := s.OIDCStore.(authn.IdentitySessionStore)
	if !ok {
		return false
	}
	sessionCookie, err := r.Cookie("gotth_mail_session")
	if err != nil || sessionCookie.Value == "" {
		return false
	}
	csrfCookie, err := r.Cookie("gotth_mail_csrf")
	if err != nil || csrfCookie.Value == "" || r.Header.Get("X-CSRF-Token") != csrfCookie.Value {
		return false
	}
	bound, ok := store.BoundSession(r.Context(), sessionCookie.Value, s.oidcNow())
	return ok && authn.ValidCSRF(bound.Session, csrfCookie.Value)
}
