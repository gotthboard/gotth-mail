package daemon

import (
	"encoding/json"
	"net/http"
	"strings"
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

func method(w http.ResponseWriter, r *http.Request, want string) bool {
	if r.Method != want {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return false
	}
	return true
}
func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
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
