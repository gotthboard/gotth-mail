// Package frontauth implements the private NGINX mail auth_http contract.
package frontauth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

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
	service       daemon.Service
	tokenDigest   [sha256.Size]byte
	postfixServer string
	postfixPort   string
	dovecotServer string
	dovecotPort   string
}

func New(service daemon.Service, token string) (*Handler, error) {
	if !validToken(token) {
		return nil, fmt.Errorf("front-auth service token must contain %d..%d bytes on one line", minTokenBytes, maxTokenBytes)
	}
	return &Handler{
		service: service, tokenDigest: sha256.Sum256([]byte(token)),
		postfixServer: "postfix", postfixPort: "25",
		dovecotServer: "dovecot", dovecotPort: "143",
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
		if !valid || recipient == "" {
			h.reject(w, "invalid recipient")
			return
		}
		response := h.service.PostfixRecipient(correlationID, recipient)
		if response.Decision != daemon.OK {
			h.rejectDecision(w, response.Decision)
			return
		}
		h.accept(w, h.postfixServer, h.postfixPort)
	case (protocol == "imap" || protocol == "smtp") && (method == "plain" || method == "login"):
		username, userOK := boundedHeader(r, "Auth-User")
		secret, secretOK := boundedHeader(r, "Auth-Pass")
		if !userOK || !secretOK || username == "" || secret == "" {
			h.reject(w, "invalid credentials")
			return
		}
		passProtocol := "imap"
		server, port := h.dovecotServer, h.dovecotPort
		if protocol == "smtp" {
			passProtocol = "submission"
			server, port = h.postfixServer, h.postfixPort
		}
		response := h.service.DovecotPassdb(correlationID, daemon.PassdbRequest{
			Username: username, Secret: secret, Protocol: passProtocol,
		})
		if response.Decision != daemon.OK {
			h.rejectDecision(w, response.Decision)
			return
		}
		h.accept(w, server, port)
	default:
		h.reject(w, "unsupported authentication")
	}
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

func (h *Handler) accept(w http.ResponseWriter, server, port string) {
	w.Header().Set("Auth-Status", "OK")
	w.Header().Set("Auth-Server", server)
	w.Header().Set("Auth-Port", port)
	w.WriteHeader(http.StatusOK)
}

func (h *Handler) rejectDecision(w http.ResponseWriter, decision daemon.Decision) {
	if decision == daemon.Defer || decision == daemon.Error {
		w.Header().Set("Auth-Wait", "3")
		h.reject(w, "authentication temporarily unavailable")
		return
	}
	h.reject(w, "authentication failed")
}

func (h *Handler) reject(w http.ResponseWriter, status string) {
	w.Header().Set("Auth-Status", status)
	w.Header().Set("Auth-Error-Code", "535 5.7.8")
	w.WriteHeader(http.StatusOK)
}

func newCorrelationID() string {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "front-auth"
	}
	return "front-auth-" + hex.EncodeToString(raw[:])
}
