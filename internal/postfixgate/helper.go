package postfixgate

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
)

type QueueHolder interface {
	Hold(context.Context, string) error
}

type Helper struct {
	Inspector QueueInspector
	Holder    QueueHolder
	TokenHash [32]byte
}

// NewHelper stores only the fixed-length helper-token digest.
// Complexity: time O(n), Omega(1), tight Theta(n); auxiliary space O(1), where
// n is the bounded secret length.
func NewHelper(inspector QueueInspector, holder QueueHolder, token string) (Helper, error) {
	if inspector == nil || holder == nil || len(token) < 32 || len(token) > 4096 || strings.TrimSpace(token) != token {
		return Helper{}, errors.New("invalid Postfix helper configuration")
	}
	return Helper{Inspector: inspector, Holder: holder, TokenHash: sha256.Sum256([]byte(token))}, nil
}

// Handler exposes only inspect and hold for one validated queue ID.
// Complexity: local time and space O(n), Omega(1), with an 8 KiB request bound;
// Postfix command costs are delegated to the injected narrow boundary.
func (h Helper) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/queue/inspect", func(w http.ResponseWriter, r *http.Request) {
		queueID, ok := h.request(w, r)
		if !ok {
			return
		}
		metadata, err := h.Inspector.Inspect(r.Context(), queueID)
		if err != nil {
			http.Error(w, "queue inspection failed", http.StatusConflict)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(metadata)
	})
	mux.HandleFunc("/v1/queue/hold", func(w http.ResponseWriter, r *http.Request) {
		queueID, ok := h.request(w, r)
		if !ok {
			return
		}
		if err := h.Holder.Hold(r.Context(), queueID); err != nil {
			http.Error(w, "queue hold failed", http.StatusConflict)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	return mux
}

// request authenticates and strictly decodes one queue selector.
// Complexity: time O(n), Omega(1), tight Theta(n); auxiliary space O(n), where
// n is capped at 8 KiB.
func (h Helper) request(w http.ResponseWriter, r *http.Request) (string, bool) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return "", false
	}
	const prefix = "Bearer "
	header := r.Header.Get("Authorization")
	if !strings.HasPrefix(header, prefix) || len(header) > len(prefix)+4096 {
		w.WriteHeader(http.StatusUnauthorized)
		return "", false
	}
	digest := sha256.Sum256([]byte(strings.TrimPrefix(header, prefix)))
	if subtle.ConstantTimeCompare(digest[:], h.TokenHash[:]) != 1 {
		w.WriteHeader(http.StatusUnauthorized)
		return "", false
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10))
	decoder.DisallowUnknownFields()
	var request struct {
		QueueID string `json:"queue_id"`
	}
	if err := decoder.Decode(&request); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return "", false
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		w.WriteHeader(http.StatusBadRequest)
		return "", false
	}
	if request.QueueID == "" {
		w.WriteHeader(http.StatusBadRequest)
		return "", false
	}
	return request.QueueID, true
}
