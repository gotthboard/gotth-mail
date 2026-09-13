package identity

import (
	"context"
	"crypto/rand"
	"crypto/sha1"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/mail"
	"strings"
	"sync"
	"time"

	"forgejo/gotthboard/gotth-mail/internal/audit"
	"forgejo/gotthboard/gotth-mail/internal/authz"
	"forgejo/gotthboard/gotth-mail/internal/daemon"
	"forgejo/gotthboard/gotth-mail/internal/store"
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
	Audit        audit.Writer
	Authorizer   authz.Authorizer
	Daemon       *daemon.Service
	Now          func() time.Time
	Secret       func() (string, error)
	DB           *sql.DB
}

func NewService(domains ...string) *Service {
	s := &Service{Mailboxes: map[string]Mailbox{}, AppPasswords: map[string]AppPassword{}, Tokens: map[string]Token{}, KnownDomains: map[string]bool{}, Now: func() time.Time { return time.Now().UTC() }, Secret: randomSecret}
	for _, d := range domains {
		s.KnownDomains[strings.ToLower(d)] = true
	}
	return s
}

func NewSQLService(ctx context.Context, db *sql.DB, domains ...string) (*Service, error) {
	s := NewService(domains...)
	s.DB = db
	if err := s.loadSQL(ctx); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Service) AddToken(id, kind, secret string) error {
	return s.AddTokenWithScopes(id, kind, secret, nil...)
}

func (s *Service) AddTokenWithScopes(id, kind, secret string, scopes ...string) error {
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
	tok := Token{ID: id, Kind: kind, Verifier: verifier, Scopes: append([]string(nil), scopes...)}
	if err := s.persistTokenLocked(context.Background(), tok); err != nil {
		return err
	}
	s.Tokens[id] = tok
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

func (s *Service) ValidateMailbox(email string) error { return s.validateMailbox(email) }

func (s *Service) AuthorizeProvision(ctx context.Context, actor authz.Actor, email string) error {
	return s.authorize(ctx, actor, "mailbox:provision", authz.Resource{Type: "mailbox", ID: email})
}

// ApplySCIMMailbox updates the runtime mailbox/passdb projection after the
// canonical SQL transaction commits. It performs no I/O and cannot reject an
// already committed resource mutation.
func (s *Service) ApplySCIMMailbox(previousEmail string, mailbox Mailbox) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := strings.ToLower(mailbox.Email)
	previousKey := strings.ToLower(previousEmail)
	if current, exists := s.Mailboxes[previousKey]; mailbox.Verifier == "" && exists {
		mailbox.Verifier = current.Verifier
	}
	if previousKey != "" && previousKey != key {
		delete(s.Mailboxes, previousKey)
		if s.Daemon != nil {
			delete(s.Daemon.Mailboxes, previousKey)
			delete(s.Daemon.AppPasswordVerifiers, previousKey)
		}
		for id, appPassword := range s.AppPasswords {
			if appPassword.MailboxID == previousKey {
				appPassword.MailboxID = key
				s.AppPasswords[id] = appPassword
			}
		}
	}
	s.Mailboxes[key] = mailbox
	s.syncDaemonMailboxLocked(mailbox)
	s.syncDaemonAppPasswordsLocked(key)
}

func (s *Service) BindDaemon(service *daemon.Service) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Daemon = service
	for _, mailbox := range s.Mailboxes {
		s.syncDaemonMailboxLocked(mailbox)
	}
	for mailboxID := range s.Mailboxes {
		s.syncDaemonAppPasswordsLocked(mailboxID)
	}
}

func (s *Service) CreateOrReplaceUser(ctx context.Context, actor authz.Actor, m Mailbox, password string) (Mailbox, error) {
	if err := s.authorize(ctx, actor, "mailbox:provision", authz.Resource{Type: "mailbox", ID: m.Email}); err != nil {
		_ = s.audit(ctx, actor, "scim.user.write", m.Email, "denied", err)
		return Mailbox{}, err
	}
	if err := s.validateMailbox(m.Email); err != nil {
		_ = s.audit(ctx, actor, "scim.user.write", m.Email, "failure", err)
		return Mailbox{}, err
	}
	if password != "" {
		v, err := HashSecret(password)
		if err != nil {
			_ = s.audit(ctx, actor, "scim.user.write", m.Email, "failure", err)
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
	key := strings.ToLower(m.Email)
	s.mu.Lock()
	old, exists := s.Mailboxes[key]
	if exists && m.Verifier == "" {
		m.Verifier = old.Verifier
	}
	if !exists {
		m.CreatedAt = now
	} else {
		m.CreatedAt = old.CreatedAt
	}
	if err := s.audit(ctx, actor, "scim.user.write", m.ID, "success", nil); err != nil {
		s.mu.Unlock()
		return Mailbox{}, err
	}
	if err := s.persistMailboxLocked(ctx, m); err != nil {
		s.mu.Unlock()
		return Mailbox{}, err
	}
	s.Mailboxes[key] = m
	s.syncDaemonMailboxLocked(m)
	s.mu.Unlock()
	return m, nil
}

func (s *Service) PatchUser(ctx context.Context, actor authz.Actor, id string, ops []PatchOperation) (Mailbox, error) {
	s.mu.Lock()
	m, ok := s.Mailboxes[strings.ToLower(id)]
	s.mu.Unlock()
	if !ok {
		err := errors.New("user not found")
		_ = s.audit(ctx, actor, "scim.user.patch", id, "failure", err)
		return Mailbox{}, err
	}
	for _, op := range ops {
		if err := applyPatch(&m, op); err != nil {
			_ = s.audit(ctx, actor, "scim.user.patch", id, "failure", err)
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
		_ = s.audit(ctx, actor, "scim.user.disable", id, "failure", err)
		return Mailbox{}, err
	}
	m.Active = false
	out, err := s.CreateOrReplaceUser(ctx, actor, m, "")
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

func (s *Service) ListAppPasswordsForActor(ctx context.Context, actor authz.Actor, mailboxID string) ([]AppPassword, error) {
	if err := s.authorize(ctx, actor, "mailbox:app_password.read", authz.Resource{Type: "mailbox", ID: mailboxID}); err != nil {
		_ = s.audit(ctx, actor, "app_password.list", mailboxID, "denied", err)
		return nil, err
	}
	return s.ListAppPasswords(mailboxID), nil
}

func (s *Service) CreateAppPassword(ctx context.Context, actor authz.Actor, mailboxID, label string) (AppPasswordCreated, error) {
	if label = strings.TrimSpace(label); label == "" {
		err := errors.New("label required")
		_ = s.audit(ctx, actor, "app_password.create", mailboxID, "failure", err)
		return AppPasswordCreated{}, err
	}
	if err := s.authorize(ctx, actor, "mailbox:app_password.create", authz.Resource{Type: "mailbox", ID: mailboxID}); err != nil {
		_ = s.audit(ctx, actor, "app_password.create", mailboxID, "denied", err)
		return AppPasswordCreated{}, err
	}
	s.mu.Lock()
	_, ok := s.Mailboxes[strings.ToLower(mailboxID)]
	s.mu.Unlock()
	if !ok {
		err := errors.New("mailbox not found")
		_ = s.audit(ctx, actor, "app_password.create", mailboxID, "failure", err)
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
	if err := s.audit(ctx, actor, "app_password.create", mailboxID, "success", nil); err != nil {
		s.mu.Unlock()
		return AppPasswordCreated{}, err
	}
	p := AppPassword{ID: id, MailboxID: strings.ToLower(mailboxID), Label: label, Verifier: verifier, CreatedAt: now}
	if err := s.persistAppPasswordLocked(ctx, p); err != nil {
		s.mu.Unlock()
		return AppPasswordCreated{}, err
	}
	s.AppPasswords[id] = p
	s.syncDaemonAppPasswordsLocked(strings.ToLower(mailboxID))
	s.mu.Unlock()
	return AppPasswordCreated{ID: id, Label: label, SecretOnce: secret, CreatedAt: now}, nil
}
func (s *Service) RevokeAppPassword(ctx context.Context, actor authz.Actor, mailboxID, tokenID string) error {
	if err := s.authorize(ctx, actor, "mailbox:app_password.revoke", authz.Resource{Type: "mailbox", ID: mailboxID}); err != nil {
		_ = s.audit(ctx, actor, "app_password.revoke", mailboxID, "denied", err)
		return err
	}
	now := s.now()
	s.mu.Lock()
	p, ok := s.AppPasswords[tokenID]
	if !ok || p.MailboxID != strings.ToLower(mailboxID) {
		s.mu.Unlock()
		err := errors.New("app password not found")
		_ = s.audit(ctx, actor, "app_password.revoke", mailboxID, "failure", err)
		return err
	}
	p.RevokedAt = &now
	if err := s.audit(ctx, actor, "app_password.revoke", mailboxID, "success", nil); err != nil {
		s.mu.Unlock()
		return err
	}
	if err := s.persistAppPasswordLocked(ctx, p); err != nil {
		s.mu.Unlock()
		return err
	}
	s.AppPasswords[tokenID] = p
	s.syncDaemonAppPasswordsLocked(strings.ToLower(mailboxID))
	s.mu.Unlock()
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
	return HashSecretBytes([]byte(secret))
}
func HashSecretBytes(secret []byte) (string, error) {
	if len(secret) < 8 {
		return "", errors.New("password too short")
	}
	return daemon.MakeDjangoPBKDF2SHA256Bytes(secret, safeToken(10), 120000), nil
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
	if (s.DB != nil || len(s.KnownDomains) > 0) && !s.KnownDomains[parts[1]] {
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
func (s *Service) audit(ctx context.Context, actor authz.Actor, action, resource, result string, cause error) error {
	if s.Audit == nil {
		return cause
	}
	code := ""
	if cause != nil {
		code = cause.Error()
	}
	if err := s.Audit.Write(ctx, audit.Event{Actor: audit.ActorRef{Type: actor.Type, ID: actor.ID}, Action: action, Resource: audit.ResourceRef{Type: "identity", ID: resource}, Result: result, ErrorCode: code, Time: s.now(), CorrelationID: "identity"}); err != nil {
		return err
	}
	return cause
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
func (s *Service) loadSQL(ctx context.Context) error {
	if s.DB == nil {
		return nil
	}
	rows, err := s.DB.QueryContext(ctx, `SELECT name FROM domains WHERE enabled=true`)
	if err != nil {
		return err
	}
	for rows.Next() {
		var domain string
		if err := rows.Scan(&domain); err != nil {
			rows.Close()
			return err
		}
		s.KnownDomains[strings.ToLower(domain)] = true
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	if err := rows.Close(); err != nil {
		return err
	}
	rows, err = s.DB.QueryContext(ctx, `SELECT d.name, m.local_part, COALESCE(m.display_name,''), m.enabled, COALESCE(m.verifier,''), COALESCE(m.scim_resource_id,''), m.created_at, m.updated_at FROM mailboxes m JOIN domains d ON d.id=m.domain_id`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var domain, local, display, verifier, scimID string
		var active bool
		var created, updated time.Time
		if err := rows.Scan(&domain, &local, &display, &active, &verifier, &scimID, &created, &updated); err != nil {
			return err
		}
		email := strings.ToLower(local + "@" + domain)
		id := email
		if scimID != "" {
			id = scimID
		}
		s.Mailboxes[email] = Mailbox{ID: id, Email: email, DisplayName: display, Active: active, Verifier: verifier, CreatedAt: created, UpdatedAt: updated}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	rows, err = s.DB.QueryContext(ctx, `SELECT label, kind, verifier, scope_json, revoked_at FROM tokens`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var id, kind, verifier, scopeJSON string
		var revoked sql.NullTime
		if err := rows.Scan(&id, &kind, &verifier, &scopeJSON, &revoked); err != nil {
			return err
		}
		var scopes []string
		_ = json.Unmarshal([]byte(scopeJSON), &scopes)
		if kind == "app_password" {
			// App passwords are loaded below with mailbox subject metadata.
			continue
		}
		s.Tokens[id] = Token{ID: id, Kind: kind, Verifier: verifier, Scopes: scopes, Revoked: revoked.Valid}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	rows, err = s.DB.QueryContext(ctx, `SELECT label, subject_id, verifier, created_at, revoked_at FROM tokens WHERE kind='app_password'`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var id, mailbox, verifier string
		var created time.Time
		var revoked sql.NullTime
		if err := rows.Scan(&id, &mailbox, &verifier, &created, &revoked); err != nil {
			return err
		}
		var rp *time.Time
		if revoked.Valid {
			t := revoked.Time
			rp = &t
		}
		s.AppPasswords[id] = AppPassword{ID: id, MailboxID: strings.ToLower(mailbox), Label: id, Verifier: verifier, CreatedAt: created, RevokedAt: rp}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	for _, m := range s.Mailboxes {
		s.syncDaemonMailboxLocked(m)
	}
	for mailbox := range s.Mailboxes {
		s.syncDaemonAppPasswordsLocked(mailbox)
	}
	return nil
}

func (s *Service) persistMailboxLocked(ctx context.Context, m Mailbox) error {
	if s.DB == nil {
		return nil
	}
	local, domain, ok := strings.Cut(strings.ToLower(m.Email), "@")
	if !ok {
		return errors.New("invalid mailbox address")
	}
	domainID := stableUUID("domain:" + domain)
	mailboxID := stableUUID("mailbox:" + strings.ToLower(m.Email))
	if _, err := s.DB.ExecContext(ctx, `INSERT INTO domains(id, name, enabled, created_at, updated_at) VALUES ($1,$2,true,$3,$4) ON CONFLICT (name) DO UPDATE SET updated_at=EXCLUDED.updated_at`, domainID, domain, m.CreatedAt, m.UpdatedAt); err != nil {
		return err
	}
	_, err := s.DB.ExecContext(ctx, `INSERT INTO mailboxes(id, domain_id, local_part, display_name, enabled, verifier, created_at, updated_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT (domain_id, local_part) DO UPDATE SET display_name=EXCLUDED.display_name, enabled=EXCLUDED.enabled, verifier=EXCLUDED.verifier, updated_at=EXCLUDED.updated_at`, mailboxID, domainID, local, nullString(m.DisplayName), m.Active, nullString(m.Verifier), m.CreatedAt, m.UpdatedAt)
	return err
}

func (s *Service) persistTokenLocked(ctx context.Context, tok Token) error {
	if s.DB == nil {
		return nil
	}
	scopes, err := json.Marshal(tok.Scopes)
	if err != nil {
		return err
	}
	var revoked sql.NullTime
	if tok.Revoked {
		revoked = sql.NullTime{Time: s.now(), Valid: true}
	}
	_, err = s.DB.ExecContext(ctx, `INSERT INTO tokens(id, subject_type, subject_id, kind, verifier, label, scope_json, created_at, revoked_at) VALUES ($1,'token',$2,$3,$4,$5,$6,$7,$8) ON CONFLICT (id) DO UPDATE SET verifier=EXCLUDED.verifier, scope_json=EXCLUDED.scope_json, revoked_at=EXCLUDED.revoked_at`, stableUUID("token:"+tok.ID), tok.ID, tok.Kind, tok.Verifier, tok.ID, string(scopes), s.now(), revoked)
	return err
}

func (s *Service) persistAppPasswordLocked(ctx context.Context, p AppPassword) error {
	if s.DB == nil {
		return nil
	}
	scopeJSON, _ := json.Marshal([]string{"mailbox:" + strings.ToLower(p.MailboxID) + ":app_password"})
	_, err := s.DB.ExecContext(ctx, `INSERT INTO tokens(id, subject_type, subject_id, kind, verifier, label, scope_json, created_at, revoked_at) VALUES ($1,'mailbox',$2,'app_password',$3,$4,$5,$6,$7) ON CONFLICT (id) DO UPDATE SET verifier=EXCLUDED.verifier, revoked_at=EXCLUDED.revoked_at`, stableUUID("app_password:"+p.ID), strings.ToLower(p.MailboxID), p.Verifier, p.ID, string(scopeJSON), p.CreatedAt, nullTimePtr(p.RevokedAt))
	return err
}

func stableUUID(seed string) string {
	h := sha1.Sum([]byte(seed))
	b := h[:16]
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	s := hex.EncodeToString(b)
	return s[0:8] + "-" + s[8:12] + "-" + s[12:16] + "-" + s[16:20] + "-" + s[20:32]
}

func nullString(v string) sql.NullString { return sql.NullString{String: v, Valid: v != ""} }
func nullTimePtr(v *time.Time) sql.NullTime {
	if v == nil {
		return sql.NullTime{}
	}
	return sql.NullTime{Time: *v, Valid: true}
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
