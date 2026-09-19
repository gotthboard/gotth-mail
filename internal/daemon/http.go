package daemon

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"forgejo/gotthboard/gotth-mail/internal/outboundpolicy"
)

func (s Service) Register(mux *http.ServeMux) {
	mux.HandleFunc("/internal/v1/postfix/domains/", func(w http.ResponseWriter, r *http.Request) {
		if !method(w, r, http.MethodGet) {
			return
		}
		write(w, s.PostfixDomain(correlationHeader(r), pathTail(r, "/internal/v1/postfix/domains/")))
	})
	mux.HandleFunc("/internal/v1/postfix/recipients/", func(w http.ResponseWriter, r *http.Request) {
		if !method(w, r, http.MethodGet) {
			return
		}
		write(w, s.PostfixRecipient(correlationHeader(r), pathTail(r, "/internal/v1/postfix/recipients/")))
	})
	mux.HandleFunc("/internal/v1/postfix/mailboxes/", func(w http.ResponseWriter, r *http.Request) {
		if !method(w, r, http.MethodGet) {
			return
		}
		write(w, s.PostfixMailbox(correlationHeader(r), pathTail(r, "/internal/v1/postfix/mailboxes/")))
	})
	mux.HandleFunc("/internal/v1/postfix/aliases/", func(w http.ResponseWriter, r *http.Request) {
		if !method(w, r, http.MethodGet) {
			return
		}
		write(w, s.PostfixAlias(correlationHeader(r), pathTail(r, "/internal/v1/postfix/aliases/")))
	})
	mux.HandleFunc("/internal/v1/postfix/sender-login", func(w http.ResponseWriter, r *http.Request) {
		if !method(w, r, http.MethodPost) {
			return
		}
		var req SenderLoginRequest
		if decode(w, r, &req) {
			write(w, s.PostfixSenderLogin(correlationHeader(r), req))
		}
	})
	mux.HandleFunc("/internal/v1/postfix/sender-policy", func(w http.ResponseWriter, r *http.Request) {
		if !method(w, r, http.MethodPost) {
			return
		}
		var req SenderLoginRequest
		if decode(w, r, &req) {
			write(w, s.PostfixSenderPolicy(correlationHeader(r), req))
		}
	})
	mux.HandleFunc("/internal/v1/postfix/outbound-policy", func(w http.ResponseWriter, r *http.Request) {
		if !method(w, r, http.MethodPost) {
			return
		}
		var req outboundpolicy.EnforcementRequest
		if decodeStrict(w, r, &req) {
			write(w, s.PostfixOutboundPolicy(r.Context(), correlationHeader(r), req))
		}
	})
	mux.HandleFunc("/internal/v1/postfix/queue/register", func(w http.ResponseWriter, r *http.Request) {
		if !method(w, r, http.MethodPost) || !s.authorizePostfixHelper(w, r) {
			return
		}
		var req outboundpolicy.QueueAdmissionRequest
		if decodeStrict(w, r, &req) {
			write(w, s.PostfixQueueAdmission(r.Context(), correlationHeader(r), req))
		}
	})
	mux.HandleFunc("/internal/v1/postfix/queue/reconcile", func(w http.ResponseWriter, r *http.Request) {
		if !method(w, r, http.MethodPost) || !s.authorizePostfixHelper(w, r) {
			return
		}
		var req struct {
			QueueID string `json:"queue_id"`
		}
		if decodeStrict(w, r, &req) {
			write(w, s.PostfixQueueReconcile(r.Context(), correlationHeader(r), req.QueueID))
		}
	})
	mux.HandleFunc("/internal/v1/postfix/rate-limit/", func(w http.ResponseWriter, r *http.Request) {
		if !method(w, r, http.MethodGet) {
			return
		}
		write(w, s.PostfixRateLimit(correlationHeader(r), pathTail(r, "/internal/v1/postfix/rate-limit/")))
	})
	mux.HandleFunc("/internal/v1/postfix/transport/", func(w http.ResponseWriter, r *http.Request) {
		if !method(w, r, http.MethodGet) {
			return
		}
		write(w, s.PostfixTransport(correlationHeader(r), pathTail(r, "/internal/v1/postfix/transport/")))
	})
	mux.HandleFunc("/internal/v1/dovecot/passdb", func(w http.ResponseWriter, r *http.Request) {
		if !method(w, r, http.MethodPost) {
			return
		}
		var req PassdbRequest
		if decode(w, r, &req) {
			write(w, s.DovecotPassdb(correlationHeader(r), req))
		}
	})
	mux.HandleFunc("/internal/v1/dovecot/userdb/", func(w http.ResponseWriter, r *http.Request) {
		if !method(w, r, http.MethodGet) {
			return
		}
		write(w, s.DovecotUserdb(correlationHeader(r), pathTail(r, "/internal/v1/dovecot/userdb/")))
	})
	mux.HandleFunc("/internal/v1/dovecot/quota", func(w http.ResponseWriter, r *http.Request) {
		if !method(w, r, http.MethodPost) {
			return
		}
		var req QuotaRequest
		if decode(w, r, &req) {
			write(w, s.DovecotQuota(correlationHeader(r), req))
		}
	})
	mux.HandleFunc("/internal/v1/dovecot/sieve/default/", func(w http.ResponseWriter, r *http.Request) {
		if !method(w, r, http.MethodGet) {
			return
		}
		write(w, s.DovecotSieve(correlationHeader(r), pathTail(r, "/internal/v1/dovecot/sieve/default/")))
	})
	mux.HandleFunc("/internal/v1/rspamd/local-domains", func(w http.ResponseWriter, r *http.Request) {
		if !method(w, r, http.MethodGet) {
			return
		}
		write(w, s.RspamdLocalDomains(correlationHeader(r)))
	})
	mux.HandleFunc("/internal/v1/rspamd/dkim/", func(w http.ResponseWriter, r *http.Request) {
		if !method(w, r, http.MethodGet) {
			return
		}
		write(w, s.RspamdDKIM(correlationHeader(r), pathTail(r, "/internal/v1/rspamd/dkim/")))
	})
	mux.HandleFunc("/internal/v1/rspamd/signing-decision", func(w http.ResponseWriter, r *http.Request) {
		if !method(w, r, http.MethodPost) {
			return
		}
		var req struct {
			Domain string `json:"domain"`
		}
		if decode(w, r, &req) {
			write(w, s.RspamdSigningDecision(correlationHeader(r), req.Domain))
		}
	})
	mux.HandleFunc("/internal/v1/rspamd/rate-signal", func(w http.ResponseWriter, r *http.Request) {
		if !method(w, r, http.MethodPost) {
			return
		}
		var req struct {
			Sender string `json:"sender"`
		}
		if decode(w, r, &req) {
			write(w, s.RspamdRateSignal(correlationHeader(r), req.Sender))
		}
	})
}

// authorizePostfixHelper verifies the privileged helper bearer in constant
// time against the configured digest.
// Complexity: time O(n), Omega(1), tight Theta(n); auxiliary space O(1), where
// n is the bounded header length.
func (s Service) authorizePostfixHelper(w http.ResponseWriter, r *http.Request) bool {
	const prefix = "Bearer "
	header := r.Header.Get("Authorization")
	if !s.postfixHelperEnabled || !strings.HasPrefix(header, prefix) || len(header) > len(prefix)+4096 {
		w.WriteHeader(http.StatusUnauthorized)
		return false
	}
	digest := sha256.Sum256([]byte(strings.TrimPrefix(header, prefix)))
	if subtle.ConstantTimeCompare(digest[:], s.postfixHelperToken[:]) != 1 {
		w.WriteHeader(http.StatusUnauthorized)
		return false
	}
	return true
}

func method(w http.ResponseWriter, r *http.Request, want string) bool {
	if r.Method != want {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return false
	}
	return true
}
func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(v); err != nil {
		write(w, Response{CorrelationID: correlationHeader(r), Decision: Error, Reason: "malformed_json", Message: "error: malformed json"})
		return false
	}
	return true
}

// decodeStrict bounds one internal request, rejects unknown authority fields,
// and requires exactly one JSON value.
// Complexity: time O(n), Omega(1), tight Theta(n); auxiliary space O(n),
// Omega(1), where n is request bytes capped at 1 MiB.
func decodeStrict(w http.ResponseWriter, r *http.Request, v any) bool {
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(v); err != nil {
		write(w, Response{CorrelationID: correlationHeader(r), Decision: Error, Reason: "malformed_json", Message: "error: malformed json"})
		return false
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		write(w, Response{CorrelationID: correlationHeader(r), Decision: Error, Reason: "malformed_json", Message: "error: malformed json"})
		return false
	}
	return true
}
func write(w http.ResponseWriter, r Response) {
	w.Header().Set("content-type", "application/json")
	_ = json.NewEncoder(w).Encode(r)
}
func pathTail(r *http.Request, prefix string) string { return strings.TrimPrefix(r.URL.Path, prefix) }
func correlationHeader(r *http.Request) string       { return r.Header.Get("X-Correlation-ID") }
