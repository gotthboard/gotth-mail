package httpui

import (
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"forgejo/gotthboard/gotth-mail/internal/authn"
	"forgejo/gotthboard/gotth-mail/internal/authz"
	"forgejo/gotthboard/gotth-mail/internal/extensionsadmin"
	"forgejo/gotthboard/gotth-mail/internal/identity"
	"forgejo/gotthboard/gotth-mail/internal/ops"
)

// Complexity: registration time O(1+R), Omega(1); auxiliary space
// O(1+S), Omega(1). No tight Theta bound for arbitrary supplied mux state.
// Local fixed-pattern/closure setup is constant; R/S include delegated ServeMux
// parsing, conflict scans, synchronization waits and tree/index allocation/growth.
// Per request time O(A+Q+J+W), Omega(1); auxiliary space O(N+B+M), Omega(1).
// Tight Theta is not established across denial/error/success paths. A is existing
// auth/session/registry work, Q audit SQL work (not bounded by LIMIT), J delegated
// JSON decoding, recursive redaction and encoding including map sorting/copies,
// W response writing/waits. N <= 1000 events; B their materialized input/output
// bytes; M other delegated auth/registry/JSON memory including recursion. B is
// unbounded: the existing reader and exporter materialize, not stream. No writes
// to durable state and no new byte cap or complete-history guarantee.
func registerExtensionAuditUI(mux *http.ServeMux, ids *identity.Service, az authz.Authorizer, sessions authn.IdentitySessionStore, now func() time.Time, service *extensionsadmin.Service) {
	// No method prefix: ServeMux GET also matches HEAD; handle GET-only explicitly.
	mux.HandleFunc("/admin/extensions/{id}/audit", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", "GET")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		id, ok := extensionAuditID(r.PathValue("id"))
		if !ok {
			http.NotFound(w, r)
			return
		}
		if _, _, ok := requireExtensionUIActor(w, r, ids, az, sessions, now, false, authz.Resource{Type: "extension", ID: id}); !ok {
			return
		}
		if r.URL.RawQuery != "" {
			http.Error(w, "audit query overrides are not supported", http.StatusBadRequest)
			return
		}
		if service == nil || service.DB == nil {
			http.Error(w, "extension audit unavailable", http.StatusServiceUnavailable)
			return
		}
		item, err := service.Get(r.Context(), id)
		if errors.Is(err, extensionsadmin.ErrNotFound) {
			http.NotFound(w, r)
			return
		}
		if err != nil {
			http.Error(w, "extension audit unavailable", http.StatusInternalServerError)
			return
		}
		events, err := (ops.SQLAuditStore{DB: service.DB}).Query(r.Context(), ops.AuditFilter{ResourceType: "extension", ResourceID: item.InstanceID}, 1000)
		if err != nil {
			http.Error(w, "extension audit unavailable", http.StatusInternalServerError)
			return
		}
		body := ops.ExportAuditJSONL(events)
		w.Header().Set("Content-Type", "application/x-ndjson; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="extension-audit.jsonl"`)
		// A disconnected client cannot receive a replacement status; never retry export.
		_, _ = io.WriteString(w, body)
	})
}

// Complexity: time/auxiliary space O(1), Omega(1), Theta(1): reject other lengths
// before scanning; exactly 36 ASCII bytes and at most 36 lowercased bytes remain.
// No dependency, UUID alias syntax or allocation proportional to hostile input.
func extensionAuditID(value string) (string, bool) {
	if len(value) != 36 {
		return "", false
	}
	for i := 0; i < len(value); i++ {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if value[i] != '-' {
				return "", false
			}
			continue
		}
		c := value[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
			return "", false
		}
	}
	return strings.ToLower(value), true
}
