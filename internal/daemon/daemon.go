package daemon

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"

	"forgejo/gotthboard/gotth-mail/internal/audit"
	"forgejo/gotthboard/gotth-mail/internal/outboundpolicy"
	"net/mail"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/crypto/pbkdf2"
)

const MaxAppPasswordVerifiers = 8

type Decision string

const (
	OK       Decision = "ok"
	NotFound Decision = "not_found"
	Reject   Decision = "reject"
	Defer    Decision = "defer"
	Error    Decision = "error"
)

type Response struct {
	CorrelationID   string            `json:"correlation_id"`
	Decision        Decision          `json:"decision"`
	Reason          string            `json:"reason"`
	Message         string            `json:"message,omitempty"`
	Targets         []string          `json:"targets,omitempty"`
	Home            string            `json:"home,omitempty"`
	UID             int               `json:"uid,omitempty"`
	GID             int               `json:"gid,omitempty"`
	QuotaBytes      int64             `json:"quota_bytes,omitempty"`
	Domains         []string          `json:"domains,omitempty"`
	Selector        string            `json:"selector,omitempty"`
	KeyPath         string            `json:"key_path,omitempty"`
	Allowed         bool              `json:"allowed,omitempty"`
	RetryAfterSec   int               `json:"retry_after_sec,omitempty"`
	Transport       string            `json:"transport,omitempty"`
	PolicyRevisions map[string]uint64 `json:"policy_revisions,omitempty"`
}

type Domain struct {
	Name               string
	Enabled            bool
	Transport          string
	DKIMSelector       string
	DKIMPrivateKeyPath string
}

type Mailbox struct {
	Address      string
	Enabled      bool
	Home         string
	UID, GID     int
	QuotaBytes   int64
	Verifier     string
	DefaultSieve string
}

type Alias struct {
	Address string
	Enabled bool
	Targets []string
}

type RateLimit struct {
	Allowed       bool
	RetryAfterSec int
}

type Service struct {
	Unavailable          bool
	Domains              map[string]Domain
	Mailboxes            map[string]Mailbox
	Aliases              map[string]Alias
	RateLimits           map[string]RateLimit
	AppPasswordVerifiers map[string][]string
	Audit                audit.Writer
	OutboundPolicy       *outboundpolicy.EnforcementService
	stateMu              *sync.RWMutex
}

// EnableConcurrentState installs the lock used by a live identity projection.
// It must be called during startup, before the service is published.
func (s *Service) EnableConcurrentState() {
	if s.stateMu == nil {
		s.stateMu = &sync.RWMutex{}
	}
}

func (s *Service) UpsertIdentityMailbox(mailbox Mailbox) {
	s.lockState()
	defer s.unlockState()
	if s.Mailboxes == nil {
		s.Mailboxes = map[string]Mailbox{}
	}
	if s.Domains == nil {
		s.Domains = map[string]Domain{}
	}
	address := normalizeAddress(mailbox.Address)
	mailbox.Address = address
	s.Mailboxes[address] = mailbox
	domain := address[strings.LastIndex(address, "@")+1:]
	if _, ok := s.Domains[domain]; !ok {
		s.Domains[domain] = Domain{Name: domain, Enabled: true}
	}
}

func (s *Service) DeleteIdentityMailbox(address string) {
	s.lockState()
	defer s.unlockState()
	address = normalizeAddress(address)
	delete(s.Mailboxes, address)
	delete(s.AppPasswordVerifiers, address)
}

func (s *Service) SetAppPasswordVerifiers(address string, verifiers []string) {
	s.lockState()
	defer s.unlockState()
	if s.AppPasswordVerifiers == nil {
		s.AppPasswordVerifiers = map[string][]string{}
	}
	s.AppPasswordVerifiers[normalizeAddress(address)] = append([]string(nil), verifiers...)
}

func (s *Service) lockState() {
	if s.stateMu != nil {
		s.stateMu.Lock()
	}
}

func (s *Service) unlockState() {
	if s.stateMu != nil {
		s.stateMu.Unlock()
	}
}

func (s Service) readStateLock() func() {
	if s.stateMu == nil {
		return func() {}
	}
	s.stateMu.RLock()
	return s.stateMu.RUnlock
}

type SenderLoginRequest struct {
	SASLUsername string `json:"sasl_username"`
	MailFrom     string `json:"mail_from"`
	ClientIP     string `json:"client_ip"`
}

type PassdbRequest struct {
	Username string `json:"username"`
	Secret   string `json:"secret"`
	Protocol string `json:"protocol"`
}

type QuotaRequest struct {
	Address    string `json:"address"`
	QuotaBytes int64  `json:"quota_bytes"`
}

// PostfixOutboundPolicy delegates to the SQL-authoritative policy service and
// maps its closed action/reason contract onto the daemon response.
// Complexity: local time O(1), Omega(1), tight Theta(1); auxiliary space O(n),
// Omega(1), where n is bounded policy revisions; delegated SQL/queue costs are
// defined by outboundpolicy.EnforcementService.Decide.
func (s Service) PostfixOutboundPolicy(ctx context.Context, correlationID string, req outboundpolicy.EnforcementRequest) Response {
	if s.OutboundPolicy == nil {
		return resp(correlationID, Defer, string(outboundpolicy.ReasonUnavailable))
	}
	decision, _ := s.OutboundPolicy.Decide(ctx, correlationID, req)
	result := resp(correlationID, Defer, string(decision.Reason))
	switch decision.Action {
	case outboundpolicy.ActionOK:
		result.Decision = OK
	case outboundpolicy.ActionReject:
		result.Decision = Reject
	case outboundpolicy.ActionDefer:
		result.Decision = Defer
	default:
		result.Decision = Defer
		result.Reason = string(outboundpolicy.ReasonUnavailable)
	}
	if len(decision.Revisions) > 0 {
		result.PolicyRevisions = make(map[string]uint64, len(decision.Revisions))
		for domain, revision := range decision.Revisions {
			result.PolicyRevisions[domain] = revision
		}
	}
	return result
}

func (s Service) PostfixDomain(correlationID, domain string) Response {
	if s.Unavailable {
		return resp(correlationID, Defer, "database_unavailable")
	}
	d, ok := s.domains()[normalizeDomain(domain)]
	if !ok {
		return resp(correlationID, NotFound, "domain_not_found")
	}
	if !d.Enabled {
		return resp(correlationID, Reject, "domain_disabled")
	}
	return resp(correlationID, OK, "domain_accepted")
}

func (s Service) PostfixRecipient(correlationID, address string) Response {
	if s.Unavailable {
		return resp(correlationID, Defer, "database_unavailable")
	}
	addr := normalizeAddress(address)
	if _, ok := s.mailboxes()[addr]; ok {
		return s.PostfixMailbox(correlationID, addr)
	}
	if _, ok := s.aliases()[addr]; ok {
		return s.PostfixAlias(correlationID, addr)
	}
	return resp(correlationID, NotFound, "recipient_not_found")
}

func (s Service) PostfixMailbox(correlationID, address string) Response {
	if s.Unavailable {
		return resp(correlationID, Defer, "database_unavailable")
	}
	m, ok := s.mailboxes()[normalizeAddress(address)]
	if !ok {
		return resp(correlationID, NotFound, "mailbox_not_found")
	}
	if !m.Enabled {
		return resp(correlationID, Reject, "mailbox_disabled")
	}
	return resp(correlationID, OK, "mailbox_accepted")
}

func (s Service) PostfixAlias(correlationID, address string) Response {
	if s.Unavailable {
		return resp(correlationID, Defer, "database_unavailable")
	}
	a, ok := s.aliases()[normalizeAddress(address)]
	if !ok {
		return resp(correlationID, NotFound, "alias_not_found")
	}
	if !a.Enabled {
		return resp(correlationID, Reject, "alias_disabled")
	}
	out := resp(correlationID, OK, "alias_expanded")
	out.Targets = append([]string(nil), a.Targets...)
	return out
}

func (s Service) PostfixSenderLogin(correlationID string, req SenderLoginRequest) Response {
	if s.Unavailable {
		return resp(correlationID, Defer, "database_unavailable")
	}
	if normalizeAddress(req.SASLUsername) == "" || normalizeAddress(req.MailFrom) == "" {
		return resp(correlationID, Error, "malformed_sender_login")
	}
	if normalizeAddress(req.SASLUsername) != normalizeAddress(req.MailFrom) {
		return resp(correlationID, Reject, "sender_login_mismatch")
	}
	return s.PostfixMailbox(correlationID, req.SASLUsername)
}

func (s Service) PostfixSenderPolicy(correlationID string, req SenderLoginRequest) Response {
	if s.Unavailable {
		return resp(correlationID, Defer, "database_unavailable")
	}
	if normalizeAddress(req.MailFrom) == "" {
		return resp(correlationID, Error, "malformed_sender_policy")
	}
	return s.PostfixMailbox(correlationID, req.MailFrom)
}

func (s Service) PostfixRateLimit(correlationID, sender string) Response {
	if s.Unavailable {
		return resp(correlationID, Defer, "database_unavailable")
	}
	r, ok := s.rateLimits()[normalizeAddress(sender)]
	if !ok || r.Allowed {
		out := resp(correlationID, OK, "rate_limit_allowed")
		out.Allowed = true
		return out
	}
	out := resp(correlationID, Reject, "rate_limit_exceeded")
	out.RetryAfterSec = r.RetryAfterSec
	return out
}

func (s Service) PostfixTransport(correlationID, domain string) Response {
	r := s.PostfixDomain(correlationID, domain)
	if r.Decision != OK {
		return r
	}
	d := s.domains()[normalizeDomain(domain)]
	if d.Transport == "" {
		d.Transport = "virtual:"
	}
	r.Transport = d.Transport
	return r
}

func (s Service) DovecotPassdb(correlationID string, req PassdbRequest) Response {
	if s.Unavailable {
		return resp(correlationID, Defer, "database_unavailable")
	}
	if req.Protocol != "imap" && req.Protocol != "submission" {
		return resp(correlationID, Error, "unsupported_protocol")
	}
	addr := normalizeAddress(req.Username)
	m, appVerifiers, ok := s.mailboxAuth(addr)
	if !ok {
		return resp(correlationID, NotFound, "mailbox_not_found")
	}
	if !m.Enabled {
		return resp(correlationID, Reject, "mailbox_disabled")
	}
	if strings.HasPrefix(req.Secret, "oidc:") || strings.Count(req.Secret, ".") == 2 && strings.HasPrefix(req.Secret, "eyJ") {
		return resp(correlationID, Reject, "oidc_token_not_mail_secret")
	}
	if VerifyDjangoPBKDF2SHA256(m.Verifier, req.Secret) == nil {
		if err := s.auditPassdb(correlationID, req, "mailbox_password", "success", ""); err != nil {
			return resp(correlationID, Defer, "audit_unavailable")
		}
		return resp(correlationID, OK, "passdb_authenticated")
	}
	if len(appVerifiers) > MaxAppPasswordVerifiers {
		s.auditPassdb(correlationID, req, "mail_secret", "failure", "app_password_verifier_limit_exceeded")
		return resp(correlationID, Error, "app_password_verifier_limit_exceeded")
	}
	for _, verifier := range appVerifiers {
		if VerifyDjangoPBKDF2SHA256(verifier, req.Secret) == nil {
			if err := s.auditPassdb(correlationID, req, "app_password", "success", ""); err != nil {
				return resp(correlationID, Defer, "audit_unavailable")
			}
			return resp(correlationID, OK, "passdb_authenticated")
		}
	}
	s.auditPassdb(correlationID, req, "mail_secret", "failure", "invalid_secret")
	return resp(correlationID, Reject, "invalid_secret")
}

func (s Service) DovecotUserdb(correlationID, address string) Response {
	m, ok := s.mailboxes()[normalizeAddress(address)]
	if s.Unavailable {
		return resp(correlationID, Defer, "database_unavailable")
	}
	if !ok {
		return resp(correlationID, NotFound, "mailbox_not_found")
	}
	if !m.Enabled {
		return resp(correlationID, Reject, "mailbox_disabled")
	}
	out := resp(correlationID, OK, "userdb_found")
	out.Home, out.UID, out.GID, out.QuotaBytes = m.Home, m.UID, m.GID, m.QuotaBytes
	return out
}

func (s Service) DovecotQuota(correlationID string, req QuotaRequest) Response {
	if s.Unavailable {
		return resp(correlationID, Defer, "database_unavailable")
	}
	if req.QuotaBytes < 0 {
		return resp(correlationID, Error, "invalid_quota")
	}
	m, ok := s.mailboxes()[normalizeAddress(req.Address)]
	if !ok {
		return resp(correlationID, NotFound, "mailbox_not_found")
	}
	if !m.Enabled {
		return resp(correlationID, Reject, "mailbox_disabled")
	}
	out := resp(correlationID, OK, "quota_updated")
	out.QuotaBytes = req.QuotaBytes
	return out
}

func (s Service) DovecotSieve(correlationID, address string) Response {
	r := s.DovecotUserdb(correlationID, address)
	if r.Decision != OK {
		return r
	}
	return resp(correlationID, OK, "sieve_default_available")
}

func (s Service) RspamdLocalDomains(correlationID string) Response {
	if s.Unavailable {
		return resp(correlationID, Defer, "database_unavailable")
	}
	out := resp(correlationID, OK, "local_domains_listed")
	for name, d := range s.domains() {
		if d.Enabled {
			out.Domains = append(out.Domains, name)
		}
	}
	return out
}

func (s Service) RspamdDKIM(correlationID, domain string) Response {
	if s.Unavailable {
		return resp(correlationID, Defer, "database_unavailable")
	}
	d, ok := s.domains()[normalizeDomain(domain)]
	if !ok {
		return resp(correlationID, NotFound, "domain_not_found")
	}
	if !d.Enabled {
		return resp(correlationID, Reject, "domain_disabled")
	}
	if d.DKIMSelector == "" || d.DKIMPrivateKeyPath == "" {
		return resp(correlationID, NotFound, "dkim_not_configured")
	}
	out := resp(correlationID, OK, "dkim_key_available")
	out.Selector = d.DKIMSelector
	out.KeyPath = d.DKIMPrivateKeyPath
	return out
}

func (s Service) RspamdSigningDecision(correlationID, domain string) Response {
	r := s.RspamdDKIM(correlationID, domain)
	if r.Decision == OK {
		r.Reason = "signing_allowed"
	}
	return r
}

func (s Service) RspamdRateSignal(correlationID, sender string) Response {
	return s.PostfixRateLimit(correlationID, sender)
}

func resp(correlationID string, d Decision, reason string) Response {
	return Response{CorrelationID: correlation(correlationID), Decision: d, Reason: reason, Message: safeMessage(d, reason)}
}

func safeMessage(d Decision, reason string) string {
	return strings.ReplaceAll(string(d)+": "+reason, "_", " ")
}

func correlation(v string) string {
	if strings.TrimSpace(v) != "" {
		return v
	}
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "corr-0000000000000000"
	}
	return "corr-" + hex.EncodeToString(b[:])
}

func (s Service) domains() map[string]Domain {
	unlock := s.readStateLock()
	defer unlock()
	out := map[string]Domain{}
	for k, v := range s.Domains {
		if v.Name == "" {
			v.Name = k
		}
		out[normalizeDomain(v.Name)] = v
	}
	return out
}
func (s Service) mailboxes() map[string]Mailbox {
	unlock := s.readStateLock()
	defer unlock()
	out := map[string]Mailbox{}
	for k, v := range s.Mailboxes {
		if v.Address == "" {
			v.Address = k
		}
		out[normalizeAddress(v.Address)] = v
	}
	return out
}
func (s Service) aliases() map[string]Alias {
	out := map[string]Alias{}
	for k, v := range s.Aliases {
		if v.Address == "" {
			v.Address = k
		}
		out[normalizeAddress(v.Address)] = v
	}
	return out
}
func (s Service) rateLimits() map[string]RateLimit {
	out := map[string]RateLimit{}
	for k, v := range s.RateLimits {
		out[normalizeAddress(k)] = v
	}
	return out
}

func (s Service) auditPassdb(correlationID string, req PassdbRequest, method, result, code string) error {
	if s.Audit == nil {
		return nil
	}
	return s.Audit.Write(context.Background(), audit.Event{
		Actor:         audit.ActorRef{Type: "dovecot", ID: req.Protocol},
		Action:        passdbAuditAction(method),
		Resource:      audit.ResourceRef{Type: "mailbox", ID: normalizeAddress(req.Username)},
		CorrelationID: correlation(correlationID),
		Result:        result,
		ErrorCode:     code,
		AfterRedacted: map[string]any{"method": method, "protocol": req.Protocol},
	})
}

func passdbAuditAction(method string) string {
	switch method {
	case "mailbox_password":
		return "mailbox_password.use"
	case "app_password":
		return "app_password.use"
	default:
		return "mail_secret.use"
	}
}

func (s Service) mailboxAuth(address string) (Mailbox, []string, bool) {
	unlock := s.readStateLock()
	defer unlock()
	address = normalizeAddress(address)
	mailbox, ok := s.Mailboxes[address]
	if !ok {
		for key, candidate := range s.Mailboxes {
			if normalizeAddress(key) == address {
				mailbox, ok = candidate, true
				break
			}
		}
	}
	if !ok {
		return Mailbox{}, nil, false
	}
	verifiers := s.AppPasswordVerifiers[address]
	if verifiers == nil {
		for key, candidate := range s.AppPasswordVerifiers {
			if normalizeAddress(key) == address {
				verifiers = candidate
				break
			}
		}
	}
	return mailbox, append([]string(nil), verifiers...), true
}

func normalizeDomain(v string) string { return strings.ToLower(strings.TrimSpace(v)) }
func normalizeAddress(v string) string {
	addr, err := mail.ParseAddress(strings.TrimSpace(v))
	if err != nil {
		return strings.ToLower(strings.TrimSpace(v))
	}
	return strings.ToLower(addr.Address)
}

func MakeDjangoPBKDF2SHA256(secret, salt string, iterations int) string {
	return MakeDjangoPBKDF2SHA256Bytes([]byte(secret), salt, iterations)
}

// MakeDjangoPBKDF2SHA256Bytes avoids an immutable string copy for callers
// handling write-only credentials. It does not retain secret.
func MakeDjangoPBKDF2SHA256Bytes(secret []byte, salt string, iterations int) string {
	dk := pbkdf2.Key(secret, []byte(salt), iterations, 32, sha256.New)
	defer clear(dk)
	return fmt.Sprintf("pbkdf2_sha256$%d$%s$%s", iterations, salt, base64.StdEncoding.EncodeToString(dk))
}

func ValidateDjangoPBKDF2SHA256(encoded string) error {
	parts := strings.Split(encoded, "$")
	if len(parts) != 4 || parts[0] != "pbkdf2_sha256" {
		return errors.New("unsupported verifier")
	}
	iterations, err := strconv.Atoi(parts[1])
	if err != nil || iterations < 1 {
		return errors.New("invalid verifier iterations")
	}
	if parts[2] == "" {
		return errors.New("invalid verifier salt")
	}
	want, err := base64.StdEncoding.DecodeString(parts[3])
	if err != nil || len(want) != 32 {
		return errors.New("invalid verifier digest")
	}
	return nil
}

func VerifyDjangoPBKDF2SHA256(encoded, secret string) error {
	if err := ValidateDjangoPBKDF2SHA256(encoded); err != nil {
		return err
	}
	parts := strings.Split(encoded, "$")
	iterations, _ := strconv.Atoi(parts[1])
	want, _ := base64.StdEncoding.DecodeString(parts[3])
	got := pbkdf2.Key([]byte(secret), []byte(parts[2]), iterations, len(want), sha256.New)
	if !hmac.Equal(got, want) {
		return errors.New("secret mismatch")
	}
	return nil
}
