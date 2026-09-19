package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"forgejo/gotthboard/gotth-mail/internal/apply"
	"forgejo/gotthboard/gotth-mail/internal/audit"
	"forgejo/gotthboard/gotth-mail/internal/authn"
	"forgejo/gotthboard/gotth-mail/internal/authz"
	"forgejo/gotthboard/gotth-mail/internal/config"
	"forgejo/gotthboard/gotth-mail/internal/daemon"
	"forgejo/gotthboard/gotth-mail/internal/diag"
	"forgejo/gotthboard/gotth-mail/internal/identity"
	"forgejo/gotthboard/gotth-mail/internal/notification"
	"forgejo/gotthboard/gotth-mail/internal/notifyruntime"
	"forgejo/gotthboard/gotth-mail/internal/ops"
	"forgejo/gotthboard/gotth-mail/internal/plugin"
	"forgejo/gotthboard/gotth-mail/internal/render"
	"forgejo/gotthboard/gotth-mail/internal/version"
	"forgejo/gotthboard/gotth-mail/internal/webmail"
	gotthoidc "github.com/gotthboard/gotth-oidc/pkg/oidc"
)

type Server struct {
	Authz                authz.Authorizer
	Config               config.Config
	Audit                *audit.MemoryWriter
	AuditDB              *sql.DB
	Plugins              plugin.Registry
	Applied              *render.Set
	Daemon               daemon.Service
	Queue                *ops.Queue
	NotificationQueue    notifyruntime.QueueController
	DNSChecks            []diag.DNSRecordCheck
	CertCheck            diag.CertCheck
	WebmailOK            bool
	OIDCClient           authn.OIDCClient
	OIDCStore            authn.StateStore
	OIDCRedirectURI      string
	OIDCNow              func() time.Time
	Identity             *identity.Service
	V3                   *ops.V3Runtime
	WebmailClient        *webmail.Client
	WebmailSender        *webmail.Sender
	NotificationRecorder notification.Recorder
	NotificationService  *notification.Service
	NotificationPrompter plugin.NotificationSink
	ApprovalService      *notifyruntime.ApprovalService
	NotificationReceiver http.Handler
	SCIM                 http.Handler
}

func (s Server) emitOperationalAlert(ctx context.Context, class string, severity notification.Severity, title, summary string, resource notification.ResourceRef) {
	if s.NotificationService == nil {
		return
	}
	id := fmt.Sprintf("runtime-%d", time.Now().UTC().UnixNano())
	_, _ = s.NotificationService.SendAlert(ctx, notification.Alert{ID: id, Class: class, Severity: severity, Title: title, Summary: summary, CorrelationID: id, Resource: resource})
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
		stage, err := version.Stage(version.Version)
		if err != nil {
			http.Error(w, "invalid build identity", http.StatusInternalServerError)
			return
		}
		writeJSON(w, map[string]any{"status": stage, "version": version.Version, "mail_stack_complete": stage == "stable"})
	})
	mux.HandleFunc("/api/v1/oidc/login", func(w http.ResponseWriter, r *http.Request) {
		if !method(w, r, "GET") {
			return
		}
		if s.OIDCClient == nil {
			http.Error(w, "OIDC unavailable", http.StatusServiceUnavailable)
			return
		}
		store := s.OIDCStore
		if store == nil {
			store = authn.NewStore()
			s.OIDCStore = store
		}
		browser := r.Header.Get("X-GOTTH-Mail-Browser-Binding")
		redirectMode := r.URL.Query().Get("mode") == "redirect"
		if browser == "" && redirectMode {
			var err error
			browser, err = authn.NewBrowserBinding()
			if err != nil {
				http.Error(w, authn.SafeOIDCError(err), http.StatusBadRequest)
				return
			}
			http.SetCookie(w, &http.Cookie{Name: "gotth_mail_oidc_binding", Value: browser, Path: "/api/v1/oidc", HttpOnly: true, Secure: secureCookieFor(s.OIDCRedirectURI), SameSite: http.SameSiteLaxMode, Expires: s.oidcNow().Add(10 * time.Minute)})
		}
		if browser == "" {
			http.Error(w, "browser binding required", http.StatusBadRequest)
			return
		}
		start, err := authn.StartLogin(r.Context(), s.OIDCClient, store, browser, r.URL.Query().Get("redirect"), s.oidcNow(), 10*time.Minute)
		if err != nil {
			http.Error(w, authn.SafeOIDCError(err), http.StatusBadRequest)
			return
		}
		if redirectMode {
			http.Redirect(w, r, start.URL, http.StatusFound)
			return
		}
		writeJSON(w, start)
	})
	mux.HandleFunc("/api/v1/oidc/callback", func(w http.ResponseWriter, r *http.Request) {
		if s.OIDCClient == nil {
			http.Error(w, "OIDC unavailable", http.StatusServiceUnavailable)
			return
		}
		store := s.OIDCStore
		if store == nil {
			http.Error(w, "oidc state store unavailable", http.StatusBadRequest)
			return
		}
		var in struct {
			State       string `json:"state"`
			Code        string `json:"code"`
			RedirectURI string `json:"redirect_uri"`
		}
		browserBinding := r.Header.Get("X-GOTTH-Mail-Browser-Binding")
		browserCallback := r.Method == http.MethodGet
		var response gotthoidc.AuthorizationResponse
		switch r.Method {
		case http.MethodPost:
			if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&in); err != nil {
				http.Error(w, "bad oidc callback", http.StatusBadRequest)
				return
			}
			response = gotthoidc.AuthorizationResponse{State: in.State, Code: in.Code, Mode: gotthoidc.ResponseModeQuery}
		case http.MethodGet:
			c, err := r.Cookie("gotth_mail_oidc_binding")
			if err != nil || c.Value == "" {
				http.Error(w, "oidc browser binding required", http.StatusBadRequest)
				return
			}
			browserBinding = c.Value
			response, err = gotthoidc.ParseCallback(r)
			if err != nil {
				http.Error(w, authn.SafeOIDCError(authn.ErrInvalidOIDCToken), http.StatusBadRequest)
				return
			}
			in.State = response.State
			in.Code = response.Code
			in.RedirectURI = s.OIDCRedirectURI
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if in.RedirectURI != s.OIDCRedirectURI {
			http.Error(w, authn.SafeOIDCError(authn.ErrInvalidOIDCState), http.StatusBadRequest)
			return
		}
		res, err := authn.CompleteCallback(r.Context(), s.OIDCClient, store, authn.CallbackInput{Response: response, BrowserBinding: browserBinding}, s.oidcNow())
		if err != nil {
			http.Error(w, authn.SafeOIDCError(err), http.StatusBadRequest)
			return
		}
		http.SetCookie(w, &http.Cookie{Name: "gotth_mail_session", Value: res.Session.ID, Path: "/", HttpOnly: true, Secure: secureCookieFor(s.OIDCRedirectURI), SameSite: http.SameSiteStrictMode, Expires: res.Session.ExpiresAt})
		http.SetCookie(w, &http.Cookie{Name: "gotth_mail_csrf", Value: res.CSRFSecret, Path: "/", HttpOnly: false, Secure: secureCookieFor(s.OIDCRedirectURI), SameSite: http.SameSiteStrictMode, Expires: res.Session.ExpiresAt})
		if browserCallback {
			http.SetCookie(w, &http.Cookie{Name: "gotth_mail_oidc_binding", Value: "", Path: "/api/v1/oidc", HttpOnly: true, Secure: secureCookieFor(s.OIDCRedirectURI), SameSite: http.SameSiteLaxMode, MaxAge: -1})
			target := res.RedirectAfterLogin
			if target == "" {
				target = "/"
			}
			http.Redirect(w, r, target, http.StatusSeeOther)
			return
		}
		writeJSON(w, map[string]any{"identity": res.Identity, "session": map[string]any{"expires_at": res.Session.ExpiresAt, "auth_method": res.Session.AuthMethod}})
	})
	identitySvc := s.identityService(auditLog)
	if s.SCIM != nil {
		mux.Handle("/scim/v2", s.SCIM)
		mux.Handle("/scim/v2/", s.SCIM)
	} else {
		mux.HandleFunc("/scim/v2", func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "SCIM unavailable", http.StatusServiceUnavailable)
		})
		mux.HandleFunc("/scim/v2/", func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "SCIM unavailable", http.StatusServiceUnavailable)
		})
	}
	s.registerIdentityAPI(mux, auditLog, identitySvc)
	s.registerV3(mux, auditLog, identitySvc)
	s.registerWebmail(mux, identitySvc)
	s.registerOutboundPolicyAdmin(mux, identitySvc)
	mux.HandleFunc("/api/v1/authz/explain", func(w http.ResponseWriter, r *http.Request) {
		if !method(w, r, "POST") {
			return
		}
		var req struct {
			Actor    authz.Actor    `json:"actor"`
			Action   authz.Action   `json:"action"`
			Resource authz.Resource `json:"resource"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
			http.Error(w, "bad authz explain request", http.StatusBadRequest)
			return
		}
		ex, _ := s.authorizer().Explain(r.Context(), req.Actor, req.Action, req.Resource)
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
		ids := s.identityService(auditLog)
		a, err := ids.AuthenticateBearer(r.Header.Get("Authorization"), "api_token")
		if err != nil {
			http.Error(w, "admin bearer token required", http.StatusUnauthorized)
			return
		}
		d, err := s.authorizer().Decide(r.Context(), a, "ops:admin", authz.Resource{Type: "ops", ID: "audit"})
		if err != nil || !d.Allow {
			http.Error(w, "admin authorization required", http.StatusForbidden)
			return
		}
		events := ops.FilterAudit(auditLog.Events, auditFilter(r))
		out := make([]any, 0, len(events))
		for _, e := range events {
			out = append(out, audit.Redact(e))
		}
		writeJSON(w, out)
	})
	notificationRecorder := s.NotificationRecorder
	if notificationRecorder == nil && s.AuditDB != nil {
		notificationRecorder = notification.SQLRecorder{DB: s.AuditDB}
	}
	mux.HandleFunc("/api/v1/notifications/deliveries", func(w http.ResponseWriter, r *http.Request) {
		if !method(w, r, "GET") {
			return
		}
		a, err := identitySvc.AuthenticateBearer(r.Header.Get("Authorization"), "api_token")
		if err != nil {
			http.Error(w, "admin bearer token required", http.StatusUnauthorized)
			return
		}
		d, err := s.authorizer().Decide(r.Context(), a, "notification:read", authz.Resource{Type: "notification", ID: "deliveries"})
		if err != nil || !d.Allow {
			http.Error(w, "notification authorization required", http.StatusForbidden)
			return
		}
		if notificationRecorder == nil {
			http.Error(w, "notification delivery recorder unavailable", http.StatusServiceUnavailable)
			return
		}
		records, err := notificationRecorder.List(r.Context())
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, records)
	})
	mux.HandleFunc("/api/v1/notifications/deliveries/", func(w http.ResponseWriter, r *http.Request) {
		if !method(w, r, "GET") {
			return
		}
		a, err := identitySvc.AuthenticateBearer(r.Header.Get("Authorization"), "api_token")
		if err != nil {
			http.Error(w, "admin bearer token required", http.StatusUnauthorized)
			return
		}
		id := strings.TrimPrefix(r.URL.Path, "/api/v1/notifications/deliveries/")
		if id == "" || strings.Contains(id, "/") {
			http.NotFound(w, r)
			return
		}
		d, err := s.authorizer().Decide(r.Context(), a, "notification:read", authz.Resource{Type: "notification_delivery", ID: id})
		if err != nil || !d.Allow {
			http.Error(w, "notification authorization required", http.StatusForbidden)
			return
		}
		if notificationRecorder == nil {
			http.Error(w, "notification delivery recorder unavailable", http.StatusServiceUnavailable)
			return
		}
		record, ok, err := notificationRecorder.Get(r.Context(), id)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if !ok {
			http.NotFound(w, r)
			return
		}
		writeJSON(w, record)
	})
	mux.HandleFunc("/api/v1/plugins", func(w http.ResponseWriter, r *http.Request) {
		if !method(w, r, "GET") {
			return
		}
		type pluginStatus struct {
			Name         string      `json:"name"`
			Seam         plugin.Seam `json:"seam"`
			Endpoint     string      `json:"endpoint"`
			Enabled      bool        `json:"enabled"`
			Capabilities []string    `json:"capabilities"`
		}
		out := make(map[string]pluginStatus, len(s.Plugins.Plugins))
		for name, registration := range s.Plugins.Plugins {
			out[name] = pluginStatus{Name: registration.Name, Seam: registration.Seam, Endpoint: registration.Endpoint, Enabled: registration.Enabled, Capabilities: append([]string(nil), registration.Capabilities...)}
		}
		writeJSON(w, out)
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
		report := ops.Doctor(r.Context(), ops.DoctorInput{ConfigOK: true, DatabaseOK: true, AuthentikOK: true, WebmailOK: webmailOK, Daemon: s.Daemon, DNSChecks: s.DNSChecks, CertCheck: cert, PluginRegistry: s.Plugins, PluginToken: r.Header.Get("X-GOTTH-Mail-Plugin-Token"), CorrelationID: r.Header.Get("X-Correlation-ID")})
		for _, check := range report.Checks {
			if check.Status != ops.Fail {
				continue
			}
			class := "doctor.failure"
			if check.Category == "TLS" {
				class = "certificate.renewal.failure"
			} else if check.Category == "plugin" {
				class = "plugin.health.failure"
			}
			s.emitOperationalAlert(r.Context(), class, notification.SeverityCritical, "Operational check failed", check.Category+" "+check.Name+" failed", notification.ResourceRef{Type: "doctor_check", ID: check.Name})
		}
		writeJSON(w, report)
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
		if s.NotificationQueue != nil {
			if live, err := s.NotificationQueue.Snapshot(r.Context(), ""); err == nil && live.Deferred > 0 {
				s.emitOperationalAlert(r.Context(), "queue.deferred", notification.SeverityWarning, "Deferred mail detected", fmt.Sprintf("deferred=%d total=%d", live.Deferred, live.Total), notification.ResourceRef{Type: "postfix_queue", ID: "default"})
			}
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

func (s Server) oidcNow() time.Time {
	if s.OIDCNow != nil {
		return s.OIDCNow().UTC()
	}
	return time.Now().UTC()
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

func secureCookieFor(rawurl string) bool {
	u, err := url.Parse(rawurl)
	return err != nil || u.Scheme != "http"
}
