package identity

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net/mail"
	"strings"
	"sync"
	"time"

	"forgejo/linus/gophermailforge/internal/audit"
	"forgejo/linus/gophermailforge/internal/authz"
	"forgejo/linus/gophermailforge/internal/daemon"
	"forgejo/linus/gophermailforge/internal/store"
)

type Mailbox struct {
	ID          string    `json:"id"`
	Email       string    `json:"email"`
	DisplayName string    `json:"display_name,omitempty"`
	Active      bool      `json:"active"`
	Verifier    string    `json:"-"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

type AppPassword struct {
	ID        string     `json:"id"`
	MailboxID string     `json:"mailbox_id"`
	Label     string     `json:"label"`
	Verifier  string     `json:"-"`
	CreatedAt time.Time  `json:"created_at"`
	RevokedAt *time.Time `json:"revoked_at,omitempty"`
}

type AppPasswordCreated struct {
	ID         string    `json:"id"`
	Label      string    `json:"label"`
	SecretOnce string    `json:"secret_once"`
	CreatedAt  time.Time `json:"created_at"`
}

type Token struct {
	ID       string
	Kind     string
	Verifier string
	Scopes   []string
	Revoked  bool
}

type Service struct {
	mu           sync.Mutex
	Mailboxes    map[string]Mailbox
	AppPasswords map[string]AppPassword
	Tokens       map[string]Token
	KnownDomains map[string]bool
	Audit        *audit.MemoryWriter
	Authorizer   authz.Authorizer
	Daemon       *daemon.Service
	Now          func() time.Time
	Secret       func() (string, error)
}

func NewService(domains ...string) *Service {
	s := &Service{Mailboxes: map[string]Mailbox{}, AppPasswords: map[string]AppPassword{}, Tokens: map[string]Token{}, KnownDomains: map[string]bool{}, Now: func() time.Time { return time.Now().UTC() }, Secret: randomSecret}
	for _, d := range domains {
		s.KnownDomains[strings.ToLower(d)] = true
	}
	return s
}

func (s *Service) AddToken(id, kind, secret string) error {
	if kind == "api_token" {
		kind = "api"
	}
	if !store.ValidateTokenKind(kind) {
		return errors.New("invalid token kind")
	}
	verifier, err := HashSecret(secret)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Tokens[id] = Token{ID: id, Kind: kind, Verifier: verifier, Scopes: []string{"*"}}
	return nil
}

func (s *Service) AuthenticateBearer(header, requiredKind string) (authz.Actor, error) {
	tokenKind := requiredKind
	actorType := requiredKind
	if requiredKind == "api_token" {
		tokenKind = "api"
	}
	if !strings.HasPrefix(header, "Bearer ") {
		return authz.Actor{}, errors.New("bearer token required")
	}
	secret := strings.TrimSpace(strings.TrimPrefix(header, "Bearer "))
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, tok := range s.Tokens {
		if tok.Revoked || tok.Kind != tokenKind {
			continue
		}
		if daemon.VerifyDjangoPBKDF2SHA256(tok.Verifier, secret) == nil {
			return authz.Actor{Type: actorType, ID: tok.ID, Scopes: append([]string(nil), tok.Scopes...)}, nil
		}
	}
	return authz.Actor{}, errors.New("invalid bearer token")
}

func (s *Service) ListUsers() []Mailbox {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Mailbox, 0, len(s.Mailboxes))
	for _, m := range s.Mailboxes {
		out = append(out, m)
	}
	return out
}
func (s *Service) GetUser(id string) (Mailbox, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	m, ok := s.Mailboxes[strings.ToLower(id)]
	return m, ok
}

func (s *Service) CreateOrReplaceUser(ctx context.Context, actor authz.Actor, m Mailbox, password string) (Mailbox, error) {
	if err := s.authorize(ctx, actor, "mailbox:provision", authz.Resource{Type: "mailbox", ID: m.Email}); err != nil {
		s.audit(ctx, actor, "scim.user.write", m.Email, "denied", err)
		return Mailbox{}, err
	}
	if err := s.validateMailbox(m.Email); err != nil {
		s.audit(ctx, actor, "scim.user.write", m.Email, "failure", err)
		return Mailbox{}, err
	}
	if password != "" {
		v, err := HashSecret(password)
		if err != nil {
			s.audit(ctx, actor, "scim.user.write", m.Email, "failure", err)
			return Mailbox{}, err
		}
		m.Verifier = v
	}
	now := s.now()
	m.Email = strings.ToLower(m.Email)
	if m.ID == "" {
		m.ID = m.Email
	}
	m.UpdatedAt = now
	s.mu.Lock()
	old, exists := s.Mailboxes[m.ID]
	if exists && m.Verifier == "" {
		m.Verifier = old.Verifier
	}
	if !exists {
		m.CreatedAt = now
	} else {
		m.CreatedAt = old.CreatedAt
	}
	s.Mailboxes[m.ID] = m
	s.syncDaemonMailboxLocked(m)
	s.mu.Unlock()
	s.audit(ctx, actor, "scim.user.write", m.ID, "success", nil)
	return m, nil
}

func (s *Service) PatchUser(ctx context.Context, actor authz.Actor, id string, ops []PatchOperation) (Mailbox, error) {
	s.mu.Lock()
	m, ok := s.Mailboxes[strings.ToLower(id)]
	s.mu.Unlock()
	if !ok {
		err := errors.New("user not found")
		s.audit(ctx, actor, "scim.user.patch", id, "failure", err)
		return Mailbox{}, err
	}
	for _, op := range ops {
		if err := applyPatch(&m, op); err != nil {
			s.audit(ctx, actor, "scim.user.patch", id, "failure", err)
			return Mailbox{}, err
		}
	}
	return s.CreateOrReplaceUser(ctx, actor, m, "")
}

func (s *Service) DisableUser(ctx context.Context, actor authz.Actor, id string) (Mailbox, error) {
	s.mu.Lock()
	m, ok := s.Mailboxes[strings.ToLower(id)]
	s.mu.Unlock()
	if !ok {
		err := errors.New("user not found")
		s.audit(ctx, actor, "scim.user.disable", id, "failure", err)
		return Mailbox{}, err
	}
	m.Active = false
	out, err := s.CreateOrReplaceUser(ctx, actor, m, "")
	if err == nil {
		s.audit(ctx, actor, "scim.user.disable", id, "success", nil)
	}
	return out, err
}

func (s *Service) ListAppPasswords(mailboxID string) []AppPassword {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []AppPassword
	for _, p := range s.AppPasswords {
		if p.MailboxID == strings.ToLower(mailboxID) {
			out = append(out, p)
		}
	}
	return out
}
func (s *Service) CreateAppPassword(ctx context.Context, actor authz.Actor, mailboxID, label string) (AppPasswordCreated, error) {
	if label = strings.TrimSpace(label); label == "" {
		err := errors.New("label required")
		s.audit(ctx, actor, "app_password.create", mailboxID, "failure", err)
		return AppPasswordCreated{}, err
	}
	if err := s.authorize(ctx, actor, "mailbox:app_password.create", authz.Resource{Type: "mailbox", ID: mailboxID}); err != nil {
		s.audit(ctx, actor, "app_password.create", mailboxID, "denied", err)
		return AppPasswordCreated{}, err
	}
	s.mu.Lock()
	_, ok := s.Mailboxes[strings.ToLower(mailboxID)]
	s.mu.Unlock()
	if !ok {
		err := errors.New("mailbox not found")
		s.audit(ctx, actor, "app_password.create", mailboxID, "failure", err)
		return AppPasswordCreated{}, err
	}
	secret, err := s.secret()
	if err != nil {
		return AppPasswordCreated{}, err
	}
	verifier, err := HashSecret(secret)
	if err != nil {
		return AppPasswordCreated{}, err
	}
	now := s.now()
	id := "app_" + safeToken(12)
	s.mu.Lock()
	s.AppPasswords[id] = AppPassword{ID: id, MailboxID: strings.ToLower(mailboxID), Label: label, Verifier: verifier, CreatedAt: now}
	s.syncDaemonAppPasswordsLocked(strings.ToLower(mailboxID))
	s.mu.Unlock()
	s.audit(ctx, actor, "app_password.create", mailboxID, "success", nil)
	return AppPasswordCreated{ID: id, Label: label, SecretOnce: secret, CreatedAt: now}, nil
}
func (s *Service) RevokeAppPassword(ctx context.Context, actor authz.Actor, mailboxID, tokenID string) error {
	if err := s.authorize(ctx, actor, "mailbox:app_password.revoke", authz.Resource{Type: "mailbox", ID: mailboxID}); err != nil {
		s.audit(ctx, actor, "app_password.revoke", mailboxID, "denied", err)
		return err
	}
	now := s.now()
	s.mu.Lock()
	p, ok := s.AppPasswords[tokenID]
	if !ok || p.MailboxID != strings.ToLower(mailboxID) {
		s.mu.Unlock()
		err := errors.New("app password not found")
		s.audit(ctx, actor, "app_password.revoke", mailboxID, "failure", err)
		return err
	}
	p.RevokedAt = &now
	s.AppPasswords[tokenID] = p
	s.syncDaemonAppPasswordsLocked(strings.ToLower(mailboxID))
	s.mu.Unlock()
	s.audit(ctx, actor, "app_password.revoke", mailboxID, "success", nil)
	return nil
}

func (s *Service) syncDaemonMailboxLocked(m Mailbox) {
	if s.Daemon == nil {
		return
	}
	if s.Daemon.Audit == nil && s.Audit != nil {
		s.Daemon.Audit = s.Audit
	}
	if s.Daemon.Mailboxes == nil {
		s.Daemon.Mailboxes = map[string]daemon.Mailbox{}
	}
	addr := strings.ToLower(m.Email)
	s.Daemon.Mailboxes[addr] = daemon.Mailbox{Address: addr, Enabled: m.Active, Home: "/mail/" + strings.ReplaceAll(addr, "@", "/"), UID: 5000, GID: 5000, Verifier: m.Verifier}
	domain := addr[strings.LastIndex(addr, "@")+1:]
	if s.Daemon.Domains == nil {
		s.Daemon.Domains = map[string]daemon.Domain{}
	}
	if _, ok := s.Daemon.Domains[domain]; !ok {
		s.Daemon.Domains[domain] = daemon.Domain{Name: domain, Enabled: true}
	}
}

func (s *Service) syncDaemonAppPasswordsLocked(mailboxID string) {
	if s.Daemon == nil {
		return
	}
	if s.Daemon.Audit == nil && s.Audit != nil {
		s.Daemon.Audit = s.Audit
	}
	if s.Daemon.AppPasswordVerifiers == nil {
		s.Daemon.AppPasswordVerifiers = map[string][]string{}
	}
	var verifiers []string
	for _, p := range s.AppPasswords {
		if p.MailboxID == mailboxID && p.RevokedAt == nil {
			verifiers = append(verifiers, p.Verifier)
		}
	}
	s.Daemon.AppPasswordVerifiers[mailboxID] = verifiers
}

func (s *Service) VerifyDovecot(mailboxID, secret string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, p := range s.AppPasswords {
		if p.MailboxID == strings.ToLower(mailboxID) && p.RevokedAt == nil && daemon.VerifyDjangoPBKDF2SHA256(p.Verifier, secret) == nil {
			return true
		}
	}
	m, ok := s.Mailboxes[strings.ToLower(mailboxID)]
	return ok && m.Active && daemon.VerifyDjangoPBKDF2SHA256(m.Verifier, secret) == nil
}

func HashSecret(secret string) (string, error) {
	if len(secret) < 8 {
		return "", errors.New("password too short")
	}
	return daemon.MakeDjangoPBKDF2SHA256(secret, safeToken(10), 120000), nil
}
func (s *Service) validateMailbox(email string) error {
	a, err := mail.ParseAddress(email)
	if err != nil || a.Address != email || strings.Count(email, "@") != 1 {
		return errors.New("invalid userName")
	}
	parts := strings.Split(strings.ToLower(email), "@")
	if !store.ValidateDomainName(parts[1]) {
		return errors.New("invalid domain")
	}
	if len(s.KnownDomains) > 0 && !s.KnownDomains[parts[1]] {
		return errors.New("domain outside allowed policy")
	}
	return nil
}
func (s *Service) authorize(ctx context.Context, actor authz.Actor, action authz.Action, r authz.Resource) error {
	az := s.Authorizer
	if az == nil {
		az = authz.StaticAuthorizer{}
	}
	d, err := az.Decide(ctx, actor, action, r)
	if err != nil {
		return err
	}
	if !d.Allow {
		return errors.New(d.Reason)
	}
	return nil
}
func (s *Service) audit(ctx context.Context, actor authz.Actor, action, resource, result string, err error) {
	if s.Audit == nil {
		return
	}
	code := ""
	if err != nil {
		code = err.Error()
	}
	_ = s.Audit.Write(ctx, audit.Event{Actor: audit.ActorRef{Type: actor.Type, ID: actor.ID}, Action: action, Resource: audit.ResourceRef{Type: "identity", ID: resource}, Result: result, ErrorCode: code, Time: s.now(), CorrelationID: "identity"})
}
func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now().UTC()
}
func (s *Service) secret() (string, error) {
	if s.Secret != nil {
		return s.Secret()
	}
	return randomSecret()
}
func randomSecret() (string, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
func safeToken(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

type PatchOperation struct {
	Op    string
	Path  string
	Value any
}

func applyPatch(m *Mailbox, op PatchOperation) error {
	path := strings.TrimPrefix(strings.ToLower(op.Path), "/")
	switch strings.ToLower(op.Op) {
	case "add", "replace":
		switch path {
		case "active":
			v, ok := op.Value.(bool)
			if !ok {
				return errors.New("active must be boolean")
			}
			m.Active = v
			return nil
		case "displayname", "name/formatted":
			v, ok := op.Value.(string)
			if !ok {
				return errors.New("displayName must be string")
			}
			m.DisplayName = v
			return nil
		case "password":
			v, ok := op.Value.(string)
			if !ok {
				return errors.New("password must be string")
			}
			h, err := HashSecret(v)
			if err != nil {
				return err
			}
			m.Verifier = h
			return nil
		}
	case "remove":
		if path == "displayname" || path == "name/formatted" {
			m.DisplayName = ""
			return nil
		}
	}
	return errors.New("unsupported patch operation or path")
}
