// Package frontauth implements the private NGINX mail auth_http contract.
package frontauth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/mail"
	"os"
	"strings"
	"time"

	"forgejo/gotthboard/gotth-mail/internal/daemon"
)

const (
	serviceTokenHeader = "X-GOTTH-Mail-Front-Token"
	maxHeaderBytes     = 1024
	maxTokenBytes      = 1024
	minTokenBytes      = 32
)

// Handler is a closed NGINX auth_http adapter. Backend addresses are compile-
// time product topology, not request-controlled routing data.
type Handler struct {
	service        daemon.Service
	tokenDigest    [sha256.Size]byte
	postfixServer  string
	postfixPort    string
	dovecotServer  string
	dovecotPort    string
	resolveBackend func(context.Context, string) (string, error)
}

func New(service daemon.Service, token string) (*Handler, error) {
	if !validToken(token) {
		return nil, fmt.Errorf("front-auth service token must contain %d..%d bytes on one line", minTokenBytes, maxTokenBytes)
	}
	return &Handler{
		service: service, tokenDigest: sha256.Sum256([]byte(token)),
		postfixServer: "postfix", postfixPort: "25",
		dovecotServer: "dovecot", dovecotPort: "143",
		resolveBackend: resolvePrivateBackend,
	}, nil
}

// LoadTokenFile reads one private regular token file without following a
// symlink. The returned token is bounded and has only its final line ending
// removed.
func LoadTokenFile(path string) (string, error) {
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return "", fmt.Errorf("front-auth service token must be a private regular file")
	}
	handle, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("open front-auth service token: %w", err)
	}
	defer handle.Close()
	data, err := io.ReadAll(io.LimitReader(handle, maxTokenBytes+2))
	if err != nil {
		return "", fmt.Errorf("read front-auth service token: %w", err)
	}
	token := strings.TrimSuffix(strings.TrimSuffix(string(data), "\n"), "\r")
	if !validToken(token) {
		return "", fmt.Errorf("front-auth service token must contain %d..%d bytes on one line", minTokenBytes, maxTokenBytes)
	}
	return token, nil
}

func validToken(token string) bool {
	if len(token) < minTokenBytes || len(token) > maxTokenBytes {
		return false
	}
	for _, value := range []byte(token) {
		if value >= 'a' && value <= 'z' || value >= 'A' && value <= 'Z' || value >= '0' && value <= '9' || value == '-' || value == '_' {
			continue
		}
		return false
	}
	return true
}

// ServeHTTP validates one bounded NGINX mail-auth request and returns only
// fixed-backend routing data. Complexity: time O(n + V), Omega(1), with no
// tight Theta established because password verification V is delegated and
// protocol-dependent; auxiliary space O(n), Omega(1), with n bounded by the
// admitted header limit.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodGet || !h.authorized(r.Header.Get(serviceTokenHeader)) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	protocol, ok := boundedHeader(r, "Auth-Protocol")
	if !ok {
		http.Error(w, "invalid auth request", http.StatusBadRequest)
		return
	}
	method, ok := boundedHeader(r, "Auth-Method")
	if !ok {
		http.Error(w, "invalid auth request", http.StatusBadRequest)
		return
	}
	correlationID := newCorrelationID()

	switch {
	case protocol == "smtp" && method == "none":
		recipient, valid := boundedHeader(r, "Auth-SMTP-To")
		if valid {
			recipient, valid = smtpRecipient(recipient)
		}
		if !valid {
			h.reject(w, "invalid recipient", "501 5.1.3")
			return
		}
		response := h.service.PostfixRecipient(correlationID, recipient)
		if response.Decision != daemon.OK {
			h.rejectRecipientDecision(w, response.Decision)
			return
		}
		h.accept(r.Context(), w, h.postfixServer, h.postfixPort, "")
	case (protocol == "imap" || protocol == "smtp") && (method == "plain" || method == "login"):
		username, userOK := boundedHeader(r, "Auth-User")
		secret, secretOK := boundedHeader(r, "Auth-Pass")
		canonicalUser, canonicalOK := canonicalUsername(username)
		if !userOK || !secretOK || !canonicalOK || secret == "" {
			h.reject(w, "invalid credentials", "535 5.7.8")
			return
		}
		passProtocol := "imap"
		server, port := h.dovecotServer, h.dovecotPort
		if protocol == "smtp" {
			passProtocol = "submission"
			server, port = h.postfixServer, h.postfixPort
		}
		response := h.service.DovecotPassdb(correlationID, daemon.PassdbRequest{
			Username: canonicalUser, Secret: secret, Protocol: passProtocol,
		})
		if response.Decision != daemon.OK {
			h.rejectAuthDecision(w, response.Decision)
			return
		}
		h.accept(r.Context(), w, server, port, canonicalUser)
	default:
		h.reject(w, "unsupported authentication", "535 5.7.8")
	}
}

// smtpRecipient extracts the reverse proxy's recipient path. NGINX forwards
// the complete original RCPT command in Auth-SMTP-To, not merely the address.
func smtpRecipient(value string) (string, bool) {
	value = strings.TrimSpace(value)
	if len(value) >= len("RCPT TO:") && strings.EqualFold(value[:len("RCPT TO:")], "RCPT TO:") {
		path := strings.TrimSpace(value[len("RCPT TO:"):])
		if !strings.HasPrefix(path, "<") {
			return "", false
		}
		closeIndex := strings.IndexByte(path, '>')
		if closeIndex <= 1 || closeIndex+1 < len(path) && path[closeIndex+1] != ' ' && path[closeIndex+1] != '\t' {
			return "", false
		}
		value = path[1:closeIndex]
	}
	if value == "" || strings.ContainsAny(value, "<>\x00\r\n") {
		return "", false
	}
	parsed, err := mail.ParseAddress(value)
	if err != nil || !strings.EqualFold(parsed.Address, value) {
		return "", false
	}
	return parsed.Address, true
}

// canonicalUsername binds the backend login name to Mail's lowercase address
// identity. Complexity: time O(n), Omega(n), tight Theta(n); auxiliary space
// O(n), Omega(n), tight Theta(n), where n is the bounded username length and
// delegated mail parsing is linear in n.
func canonicalUsername(value string) (string, bool) {
	value = strings.TrimSpace(value)
	if value == "" || strings.ContainsAny(value, "<>\x00\r\n") {
		return "", false
	}
	parsed, err := mail.ParseAddress(value)
	if err != nil || !strings.EqualFold(parsed.Address, value) {
		return "", false
	}
	return strings.ToLower(parsed.Address), true
}

func (h *Handler) authorized(token string) bool {
	if !validToken(token) {
		return false
	}
	digest := sha256.Sum256([]byte(token))
	return subtle.ConstantTimeCompare(digest[:], h.tokenDigest[:]) == 1
}

func boundedHeader(r *http.Request, name string) (string, bool) {
	values := r.Header.Values(name)
	if len(values) != 1 || len(values[0]) > maxHeaderBytes || strings.ContainsAny(values[0], "\r\n\x00") {
		return "", false
	}
	return values[0], true
}

// accept resolves one fixed backend and emits the bounded NGINX success
// contract. Complexity: time O(R), Omega(1), with no tight Theta established
// because DNS is delegated; auxiliary space O(R), Omega(1), where R is the
// bounded resolver result count.
func (h *Handler) accept(ctx context.Context, w http.ResponseWriter, server, port, username string) {
	address, err := h.resolveBackend(ctx, server)
	if err != nil {
		h.temporary(w)
		return
	}
	w.Header().Set("Auth-Status", "OK")
	w.Header().Set("Auth-Server", address)
	w.Header().Set("Auth-Port", port)
	if username != "" {
		w.Header().Set("Auth-User", username)
	}
	w.WriteHeader(http.StatusOK)
}

func resolvePrivateBackend(parent context.Context, host string) (string, error) {
	ctx, cancel := context.WithTimeout(parent, 2*time.Second)
	defer cancel()
	addresses, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return "", err
	}
	for _, address := range addresses {
		ipv4 := address.IP.To4()
		if ipv4 != nil && ipv4.IsPrivate() {
			return ipv4.String(), nil
		}
	}
	return "", fmt.Errorf("backend did not resolve to private IPv4")
}

// rejectAuthDecision maps a daemon decision to the documented NGINX SMTP
// response contract. Complexity: time and auxiliary space O(1), Omega(1),
// tight Theta(1).
func (h *Handler) rejectAuthDecision(w http.ResponseWriter, decision daemon.Decision) {
	if decision == daemon.Defer || decision == daemon.Error {
		h.temporary(w)
		return
	}
	h.reject(w, "authentication failed", "535 5.7.8")
}

// rejectRecipientDecision preserves temporary failures while returning a
// recipient-specific permanent code for authoritative denial. Complexity:
// time and auxiliary space O(1), Omega(1), tight Theta(1).
func (h *Handler) rejectRecipientDecision(w http.ResponseWriter, decision daemon.Decision) {
	if decision == daemon.Defer || decision == daemon.Error {
		h.temporary(w)
		return
	}
	h.reject(w, "authentication failed", "550 5.1.1")
}

// temporary emits a retryable NGINX mail-auth response. Complexity: time and
// auxiliary space O(1), Omega(1), tight Theta(1).
func (h *Handler) temporary(w http.ResponseWriter) {
	w.Header().Set("Auth-Wait", "3")
	h.reject(w, "authentication temporarily unavailable", "451 4.3.0")
}

// reject emits one explicit NGINX mail-auth failure. Complexity: time and
// auxiliary space O(1), Omega(1), tight Theta(1).
func (h *Handler) reject(w http.ResponseWriter, status, errorCode string) {
	w.Header().Set("Auth-Status", status)
	w.Header().Set("Auth-Error-Code", errorCode)
	w.WriteHeader(http.StatusOK)
}

func newCorrelationID() string {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "front-auth"
	}
	return "front-auth-" + hex.EncodeToString(raw[:])
}
