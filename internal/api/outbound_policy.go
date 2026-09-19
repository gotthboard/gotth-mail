package api

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"forgejo/gotthboard/gotth-mail/internal/audit"
	"forgejo/gotthboard/gotth-mail/internal/authz"
	"forgejo/gotthboard/gotth-mail/internal/identity"
	"forgejo/gotthboard/gotth-mail/internal/outboundpolicy"
)

const maxOutboundPolicyAdminRequestBytes = 16 << 10

type outboundPolicyAdminRequest struct {
	Domain       string               `json:"domain"`
	Scope        outboundpolicy.Scope `json:"scope"`
	Confirmation string               `json:"confirmation,omitempty"`
}

// registerOutboundPolicyAdmin exposes the SQL-authoritative preview/confirm
// boundary only to an API token authorized for the selected domain.
// Complexity: local time and space O(n), bounded by the request ceiling;
// policy and authorization costs are delegated to their owning services.
func (s Server) registerOutboundPolicyAdmin(mux *http.ServeMux, ids *identity.Service) {
	requireDomainAdmin := func(w http.ResponseWriter, r *http.Request, domain string) (audit.ActorRef, bool) {
		actor, err := ids.AuthenticateBearer(r.Header.Get("Authorization"), "api_token")
		if err != nil {
			http.Error(w, "admin bearer token required", http.StatusUnauthorized)
			return audit.ActorRef{}, false
		}
		decision, err := s.authorizer().Decide(r.Context(), actor, "domain:admin", authz.Resource{Type: "domain", ID: domain})
		if err != nil || !decision.Allow {
			http.Error(w, "domain authorization required", http.StatusForbidden)
			return audit.ActorRef{}, false
		}
		return audit.ActorRef{Type: actor.Type, ID: actor.ID}, true
	}
	mux.HandleFunc("/api/v1/domains/outbound-policy/preview", func(w http.ResponseWriter, r *http.Request) {
		if !method(w, r, http.MethodPost) {
			return
		}
		var request outboundPolicyAdminRequest
		if !decodeOutboundPolicyAdmin(w, r, &request) {
			return
		}
		if _, ok := requireDomainAdmin(w, r, request.Domain); !ok {
			return
		}
		if s.AuditDB == nil {
			http.Error(w, "outbound policy administration unavailable", http.StatusServiceUnavailable)
			return
		}
		plan, err := (outboundpolicy.AdminService{DB: s.AuditDB}).Preview(r.Context(), request.Domain, request.Scope)
		if err != nil {
			http.Error(w, "outbound policy preview failed", http.StatusBadRequest)
			return
		}
		writeJSON(w, plan)
	})
	mux.HandleFunc("/api/v1/domains/outbound-policy/apply", func(w http.ResponseWriter, r *http.Request) {
		if !method(w, r, http.MethodPost) {
			return
		}
		var request outboundPolicyAdminRequest
		if !decodeOutboundPolicyAdmin(w, r, &request) {
			return
		}
		actor, ok := requireDomainAdmin(w, r, request.Domain)
		if !ok {
			return
		}
		if s.AuditDB == nil {
			http.Error(w, "outbound policy administration unavailable", http.StatusServiceUnavailable)
			return
		}
		result, err := (outboundpolicy.AdminService{DB: s.AuditDB}).Apply(r.Context(), actor, r.Header.Get("X-Correlation-ID"), request.Domain, request.Scope, request.Confirmation)
		if err != nil {
			http.Error(w, "outbound policy apply failed", http.StatusBadRequest)
			return
		}
		writeJSON(w, result)
	})
}

// decodeOutboundPolicyAdmin accepts exactly one bounded JSON object.
// Complexity: time and space O(n), where n is at most 16 KiB.
func decodeOutboundPolicyAdmin(w http.ResponseWriter, r *http.Request, out *outboundPolicyAdminRequest) bool {
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxOutboundPolicyAdminRequestBytes))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(out); err != nil {
		http.Error(w, "bad outbound policy request", http.StatusBadRequest)
		return false
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		http.Error(w, "bad outbound policy request", http.StatusBadRequest)
		return false
	}
	return true
}
