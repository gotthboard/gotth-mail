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

	"forgejo/gotthboard/gotth-mail/internal/outboundpolicy"
)

type QueueHolder interface {
	Hold(context.Context, string) error
}

type QueueReleaser interface {
	Release(context.Context, string) error
}

type QueueOperator interface {
	Snapshot(context.Context, string) (outboundpolicy.QueueSnapshot, error)
	Flush(context.Context) error
	Retry(context.Context, string) error
}

type Helper struct {
	Inspector        QueueInspector
	Holder           QueueHolder
	Releaser         QueueReleaser
	Operator         QueueOperator
	TokenHash        [32]byte
	ReleaseTokenHash [32]byte
}

// NewHelper stores only the fixed-length helper-token digest.
// Complexity: time O(n), Omega(1), tight Theta(n); auxiliary space O(1), where
// n is the bounded secret length.
func NewHelper(inspector QueueInspector, holder QueueHolder, releaser QueueReleaser, operator QueueOperator, token, releaseToken string) (Helper, error) {
	if inspector == nil || holder == nil || releaser == nil || operator == nil || len(token) < 32 || len(token) > 4096 || strings.TrimSpace(token) != token || len(releaseToken) < 32 || len(releaseToken) > 4096 || strings.TrimSpace(releaseToken) != releaseToken || token == releaseToken {
		return Helper{}, errors.New("invalid Postfix helper configuration")
	}
	return Helper{Inspector: inspector, Holder: holder, Releaser: releaser, Operator: operator, TokenHash: sha256.Sum256([]byte(token)), ReleaseTokenHash: sha256.Sum256([]byte(releaseToken))}, nil
}

// Handler exposes inspect/hold under the delivery credential and release under
// a distinct credential unavailable to Postfix pipe(8) services.
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
	mux.HandleFunc("/v1/queue/release", func(w http.ResponseWriter, r *http.Request) {
		queueID, ok := h.requestWithHash(w, r, h.ReleaseTokenHash)
		if !ok {
			return
		}
		if err := h.Releaser.Release(r.Context(), queueID); err != nil {
			http.Error(w, "queue release failed", http.StatusConflict)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("/v1/queue/summary", func(w http.ResponseWriter, r *http.Request) {
		queueID, ok := h.optionalRequestWithHash(w, r, h.TokenHash)
		if !ok {
			return
		}
		summary, err := h.Operator.Snapshot(r.Context(), queueID)
		if err != nil {
			http.Error(w, "queue snapshot failed", http.StatusConflict)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(summary)
	})
	mux.HandleFunc("/v1/queue/flush", func(w http.ResponseWriter, r *http.Request) {
		queueID, ok := h.optionalRequestWithHash(w, r, h.ReleaseTokenHash)
		if !ok {
			return
		}
		if queueID != "" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if err := h.Operator.Flush(r.Context()); err != nil {
			http.Error(w, "queue flush failed", http.StatusConflict)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("/v1/queue/retry", func(w http.ResponseWriter, r *http.Request) {
		queueID, ok := h.requestWithHash(w, r, h.ReleaseTokenHash)
		if !ok {
			return
		}
		if err := h.Operator.Retry(r.Context(), queueID); err != nil {
			http.Error(w, "queue retry failed", http.StatusConflict)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	return mux
}

func (h Helper) optionalRequestWithHash(w http.ResponseWriter, r *http.Request, tokenHash [32]byte) (string, bool) {
	return h.decodeRequest(w, r, tokenHash, true)
}

// request authenticates and strictly decodes one queue selector.
// Complexity: time O(n), Omega(1), tight Theta(n); auxiliary space O(n), where
// n is capped at 8 KiB.
func (h Helper) request(w http.ResponseWriter, r *http.Request) (string, bool) {
	return h.requestWithHash(w, r, h.TokenHash)
}

// requestWithHash authenticates and strictly decodes one queue selector using
// the credential assigned to that operation class.
// Complexity: time O(n), Omega(1), tight Theta(n); auxiliary space O(n), where
// n is capped at 8 KiB.
func (h Helper) requestWithHash(w http.ResponseWriter, r *http.Request, tokenHash [32]byte) (string, bool) {
	return h.decodeRequest(w, r, tokenHash, false)
}

func (h Helper) decodeRequest(w http.ResponseWriter, r *http.Request, tokenHash [32]byte, optional bool) (string, bool) {
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
	if subtle.ConstantTimeCompare(digest[:], tokenHash[:]) != 1 {
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
	if request.QueueID == "" && !optional {
		w.WriteHeader(http.StatusBadRequest)
		return "", false
	}
	return request.QueueID, true
}
