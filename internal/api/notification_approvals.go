package api

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"forgejo/gotthboard/gotth-mail/internal/authz"
	"forgejo/gotthboard/gotth-mail/internal/identity"
	"forgejo/gotthboard/gotth-mail/internal/notification"
	"forgejo/gotthboard/gotth-mail/internal/notifyruntime"
)

type queueApprovalInput struct {
	ExternalActorID string `json:"external_actor_id"`
	QueueID         string `json:"queue_id,omitempty"`
}

func (s Server) registerNotificationApprovals(mux *http.ServeMux, ids *identity.Service) {
	register := func(path string, action authz.Action) {
		mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
			if !method(w, r, http.MethodPost) {
				return
			}
			if s.ApprovalService == nil {
				http.Error(w, "notification approval unavailable", http.StatusServiceUnavailable)
				return
			}
			initiator, err := ids.AuthenticateBearer(r.Header.Get("Authorization"), "api_token")
			if err != nil {
				http.Error(w, "admin bearer token required", http.StatusUnauthorized)
				return
			}
			var in queueApprovalInput
			decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10))
			decoder.DisallowUnknownFields()
			if err := decoder.Decode(&in); err != nil {
				http.Error(w, "invalid approval request", http.StatusBadRequest)
				return
			}
			var trailing any
			if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
				http.Error(w, "invalid approval request", http.StatusBadRequest)
				return
			}
			in.ExternalActorID = strings.TrimSpace(in.ExternalActorID)
			in.QueueID = strings.TrimSpace(in.QueueID)
			resourceID := "default"
			if action == "queue:retry" {
				resourceID = in.QueueID
			}
			correlationID := safeCorrelationID(r.Header.Get("X-Correlation-ID"))
			if in.ExternalActorID == "" || len(in.ExternalActorID) > 128 || resourceID == "" || correlationID == "" {
				http.Error(w, "complete approval request required", http.StatusBadRequest)
				return
			}
			resource := authz.Resource{Type: "postfix_queue", ID: resourceID}
			decision, err := s.authorizer().Decide(r.Context(), initiator, "notification:approval.create", resource)
			if err != nil || !decision.Allow {
				http.Error(w, "notification approval authorization required", http.StatusForbidden)
				return
			}
			title, summary := "Approve queue flush", "Schedule immediate delivery of all queued mail"
			if action == "queue:retry" {
				title, summary = "Approve queue retry", "Schedule immediate delivery of queue message "+resourceID
			}
			created, err := s.ApprovalService.RequestTelegramApproval(r.Context(), notifyruntime.TelegramApprovalRequest{
				TransportActor: notification.TransportActor{Transport: "telegram", ExternalID: in.ExternalActorID},
				Action:         action, Resource: resource, CorrelationID: correlationID,
				ExpiresAt: time.Now().UTC().Add(5 * time.Minute), Title: title, Summary: summary,
			})
			if err != nil {
				http.Error(w, "approval request rejected", http.StatusBadRequest)
				return
			}
			w.Header().Set("content-type", "application/json")
			w.WriteHeader(http.StatusAccepted)
			writeJSON(w, map[string]any{"approval_id": created.ID, "status": "pending", "action": created.Action, "resource": created.Resource})
		})
	}
	register("/api/v1/queue/flush", "queue:flush")
	register("/api/v1/queue/retry", "queue:retry")
}

func safeCorrelationID(value string) string {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > 128 {
		return ""
	}
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || strings.ContainsRune("._:@/-", r) {
			continue
		}
		return ""
	}
	return value
}
