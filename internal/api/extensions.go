package api

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"forgejo/gotthboard/gotth-mail/internal/audit"
	"forgejo/gotthboard/gotth-mail/internal/authz"
	"forgejo/gotthboard/gotth-mail/internal/extensionsadmin"
	"forgejo/gotthboard/gotth-mail/internal/identity"
)

func (s Server) registerExtensions(mux *http.ServeMux, ids *identity.Service) {
	requireAdmin := func(w http.ResponseWriter, r *http.Request) (audit.ActorRef, bool) {
		a, err := ids.AuthenticateBearer(r.Header.Get("Authorization"), "api_token")
		if err != nil {
			http.Error(w, "admin bearer token required", http.StatusUnauthorized)
			return audit.ActorRef{}, false
		}
		decision, err := s.authorizer().Decide(r.Context(), a, "ops:admin", authz.Resource{Type: "extensions", ID: extensionsadmin.Product})
		if err != nil || !decision.Allow {
			http.Error(w, "admin authorization required", http.StatusForbidden)
			return audit.ActorRef{}, false
		}
		return audit.ActorRef{Type: a.Type, ID: a.ID}, true
	}

	mux.HandleFunc("/api/v1/extensions", func(w http.ResponseWriter, r *http.Request) {
		if s.Extensions == nil {
			http.Error(w, "extension administrator unavailable", http.StatusServiceUnavailable)
			return
		}
		actor, ok := requireAdmin(w, r)
		if !ok {
			return
		}
		switch r.Method {
		case http.MethodGet:
			items, err := s.Extensions.List(r.Context())
			if err != nil {
				writeExtensionError(w, err)
				return
			}
			writeJSON(w, map[string]any{"extensions": items})
		case http.MethodPost:
			var input extensionsadmin.InstallRequest
			if err := decodeExtensionJSON(w, r, &input); err != nil {
				http.Error(w, "invalid extension installation", http.StatusBadRequest)
				return
			}
			if input.CorrelationID == "" {
				input.CorrelationID = r.Header.Get("X-Correlation-ID")
			}
			result, err := s.Extensions.Install(r.Context(), actor, input)
			if err != nil {
				writeExtensionError(w, err)
				return
			}
			w.Header().Set("content-type", "application/json")
			w.WriteHeader(http.StatusCreated)
			writeJSON(w, result)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	})

	mux.HandleFunc("/api/v1/extensions/", func(w http.ResponseWriter, r *http.Request) {
		if s.Extensions == nil {
			http.Error(w, "extension administrator unavailable", http.StatusServiceUnavailable)
			return
		}
		actor, ok := requireAdmin(w, r)
		if !ok {
			return
		}
		parts := strings.Split(strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/v1/extensions/"), "/"), "/")
		if len(parts) == 1 && parts[0] != "" && r.Method == http.MethodGet {
			result, err := s.Extensions.Get(r.Context(), parts[0])
			if err != nil {
				writeExtensionError(w, err)
				return
			}
			writeJSON(w, result)
			return
		}
		if len(parts) < 2 || parts[0] == "" || r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		id, operation := parts[0], strings.Join(parts[1:], "/")
		var result extensionsadmin.Instance
		var preview extensionsadmin.Preview
		var err error
		switch operation {
		case "configure/preview":
			var input extensionsadmin.ConfigureInput
			if decodeExtensionJSON(w, r, &input) != nil {
				http.Error(w, "invalid extension configuration", http.StatusBadRequest)
				return
			}
			preview, err = s.Extensions.PreviewConfigure(r.Context(), actor, id, input)
		case "configure/apply":
			var input struct {
				PreviewID     string            `json:"preview_id"`
				Confirmation  string            `json:"confirmation"`
				Configuration map[string]any    `json:"configuration"`
				Secrets       map[string]string `json:"secrets,omitempty"`
			}
			if decodeExtensionJSON(w, r, &input) != nil {
				http.Error(w, "invalid extension configuration", http.StatusBadRequest)
				return
			}
			result, err = s.Extensions.ApplyConfigure(r.Context(), actor, input.PreviewID, input.Confirmation, extensionsadmin.ConfigureInput{Configuration: input.Configuration, Secrets: input.Secrets})
		case "test":
			result, err = s.Extensions.Test(r.Context(), actor, id)
		case "enable":
			result, err = s.Extensions.Enable(r.Context(), actor, id)
		case "disable":
			result, err = s.Extensions.Disable(r.Context(), actor, id)
		case "update/preview":
			var input extensionsadmin.UpdateInput
			if decodeExtensionJSON(w, r, &input) != nil {
				http.Error(w, "invalid extension update", http.StatusBadRequest)
				return
			}
			preview, err = s.Extensions.PreviewUpdate(r.Context(), actor, id, input)
		case "update/apply":
			var input previewApply
			if decodeExtensionJSON(w, r, &input) != nil {
				http.Error(w, "invalid extension update", http.StatusBadRequest)
				return
			}
			result, err = s.Extensions.ApplyUpdate(r.Context(), actor, input.PreviewID, input.Confirmation)
		case "rollback":
			var input struct {
				Confirmation string `json:"confirmation"`
			}
			if decodeExtensionJSON(w, r, &input) != nil {
				http.Error(w, "invalid extension rollback", http.StatusBadRequest)
				return
			}
			result, err = s.Extensions.Rollback(r.Context(), actor, id, input.Confirmation)
		case "secrets/delete/preview":
			preview, err = s.Extensions.PreviewDeleteSecrets(r.Context(), actor, id)
		case "secrets/delete/apply":
			var input previewApply
			if decodeExtensionJSON(w, r, &input) != nil {
				http.Error(w, "invalid secret deletion", http.StatusBadRequest)
				return
			}
			result, err = s.Extensions.ApplyDeleteSecrets(r.Context(), actor, input.PreviewID, input.Confirmation)
		case "uninstall/preview":
			preview, err = s.Extensions.PreviewUninstall(r.Context(), actor, id)
		case "uninstall/apply":
			var input previewApply
			if decodeExtensionJSON(w, r, &input) != nil {
				http.Error(w, "invalid extension uninstall", http.StatusBadRequest)
				return
			}
			err = s.Extensions.ApplyUninstall(r.Context(), actor, input.PreviewID, input.Confirmation)
			if err == nil {
				writeJSON(w, map[string]bool{"uninstalled": true})
				return
			}
		default:
			http.NotFound(w, r)
			return
		}
		if err != nil {
			writeExtensionError(w, err)
			return
		}
		if preview.ID != "" {
			writeJSON(w, preview)
			return
		}
		writeJSON(w, result)
	})
}

type previewApply struct {
	PreviewID    string `json:"preview_id"`
	Confirmation string `json:"confirmation"`
}

func decodeExtensionJSON(w http.ResponseWriter, r *http.Request, target any) error {
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	decoder.DisallowUnknownFields()
	decoder.UseNumber()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("trailing JSON")
	}
	return nil
}

func writeExtensionError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, extensionsadmin.ErrNotFound):
		http.Error(w, "extension not found", http.StatusNotFound)
	case errors.Is(err, extensionsadmin.ErrConfirmation), errors.Is(err, extensionsadmin.ErrConflict), errors.Is(err, extensionsadmin.ErrUnhealthy):
		http.Error(w, err.Error(), http.StatusConflict)
	case errors.Is(err, extensionsadmin.ErrUnavailable):
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
	default:
		http.Error(w, "extension operation failed", http.StatusBadRequest)
	}
}
