package authn

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	gotthoidc "github.com/gotthboard/gotth-oidc/pkg/oidc"
)

var (
	ErrInvalidOIDCState    = errors.New("invalid oidc state")
	ErrInvalidOIDCToken    = errors.New("invalid oidc token")
	ErrUnsafeTokenLogValue = errors.New("oidc failure must not expose token")
)

type OIDCClient interface {
	Begin() (gotthoidc.Authorization, error)
	CompleteResponse(context.Context, gotthoidc.AuthorizationResponse, gotthoidc.ProtectedAttempt) (gotthoidc.Identity, error)
}

type LoginAttempt struct {
	Protected          gotthoidc.ProtectedAttempt
	BrowserBindingHash [sha256.Size]byte
	RedirectAfterLogin string
	CreatedAt          time.Time
	ExpiresAt          time.Time
	UsedAt             *time.Time
}

type Identity struct {
	Subject string   `json:"Subject"`
	Issuer  string   `json:"Issuer"`
	Email   string   `json:"Email"`
	Name    string   `json:"Name"`
	Groups  []string `json:"Groups"`
}

type Session struct {
	ID             string
	IdentityRefID  string
	CreatedAt      time.Time
	ExpiresAt      time.Time
	LastSeenAt     time.Time
	CSRFSecretHash string
	AuthMethod     string
}

type StateStore interface {
	PutAttempt(context.Context, LoginAttempt) error
	ConsumeAttempt(context.Context, string, string, time.Time) (LoginAttempt, error)
	PutSession(context.Context, Session) error
	Session(context.Context, string) (Session, bool)
}

type Store struct {
	mu       sync.Mutex
	attempts map[[sha256.Size]byte]LoginAttempt
	sessions map[string]Session
}

func NewStore() *Store {
	return &Store{attempts: map[[sha256.Size]byte]LoginAttempt{}, sessions: map[string]Session{}}
}

func (s *Store) PutAttempt(_ context.Context, attempt LoginAttempt) error {
	if s == nil {
		return fmt.Errorf("OIDC store is unavailable")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ensure()
	if _, exists := s.attempts[attempt.Protected.StateHash]; exists {
		return fmt.Errorf("OIDC attempt already exists")
	}
	s.attempts[attempt.Protected.StateHash] = attempt
	return nil
}

func (s *Store) Session(_ context.Context, id string) (Session, bool) {
	if s == nil {
		return Session{}, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ensure()
	session, ok := s.sessions[id]
	return session, ok
}

// ConsumeAttempt is O(1) expected time under the map lock. Comparison of the
// browser-binding digest is constant-time; the one state transition is atomic.
func (s *Store) ConsumeAttempt(_ context.Context, state, browserBinding string, now time.Time) (LoginAttempt, error) {
	if s == nil {
		return LoginAttempt{}, ErrInvalidOIDCState
	}
	stateHash := sha256.Sum256([]byte(state))
	browserHash := sha256.Sum256([]byte(browserBinding))
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ensure()
	attempt, ok := s.attempts[stateHash]
	if !ok || attempt.UsedAt != nil || now.After(attempt.ExpiresAt) || subtle.ConstantTimeCompare(attempt.BrowserBindingHash[:], browserHash[:]) != 1 {
		return LoginAttempt{}, ErrInvalidOIDCState
	}
	used := now
	attempt.UsedAt = &used
	s.attempts[stateHash] = attempt
	return attempt, nil
}

func (s *Store) PutSession(_ context.Context, session Session) error {
	if s == nil {
		return fmt.Errorf("OIDC store is unavailable")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ensure()
	s.sessions[session.ID] = session
	return nil
}

func (s *Store) ensure() {
	if s.attempts == nil {
		s.attempts = map[[sha256.Size]byte]LoginAttempt{}
	}
	if s.sessions == nil {
		s.sessions = map[string]Session{}
	}
}

type LoginStart struct {
	StateID string
	Nonce   string
	URL     string
}

type CallbackInput struct {
	Response       gotthoidc.AuthorizationResponse
	BrowserBinding string
}

type CallbackResult struct {
	Identity           Identity
	Session            Session
	RedirectAfterLogin string
}

// StartLogin is O(1) aside from the library's fixed-size cryptography and one
// store write. It persists only the gotth-oidc protected representation.
func StartLogin(ctx context.Context, client OIDCClient, store StateStore, browserBinding, redirectAfter string, now time.Time, ttl time.Duration) (LoginStart, error) {
	if client == nil || store == nil {
		return LoginStart{}, fmt.Errorf("OIDC client and store are required")
	}
	if browserBinding == "" || len(browserBinding) > 1024 || ttl <= 0 || ttl > 30*time.Minute {
		return LoginStart{}, ErrInvalidOIDCState
	}
	redirectAfter, err := localRedirect(redirectAfter)
	if err != nil {
		return LoginStart{}, ErrInvalidOIDCState
	}
	authorization, err := client.Begin()
	if err != nil {
		return LoginStart{}, err
	}
	parsed, err := url.Parse(authorization.URL)
	if err != nil {
		return LoginStart{}, fmt.Errorf("parse OIDC authorization URL: %w", err)
	}
	state, nonce := parsed.Query().Get("state"), parsed.Query().Get("nonce")
	if state == "" || nonce == "" || sha256.Sum256([]byte(state)) != authorization.Attempt.StateHash {
		return LoginStart{}, fmt.Errorf("gotth-oidc returned inconsistent authorization material")
	}
	attempt := LoginAttempt{
		Protected: authorization.Attempt, BrowserBindingHash: sha256.Sum256([]byte(browserBinding)),
		RedirectAfterLogin: redirectAfter, CreatedAt: now.UTC(), ExpiresAt: now.UTC().Add(ttl),
	}
	if err := store.PutAttempt(ctx, attempt); err != nil {
		return LoginStart{}, err
	}
	return LoginStart{StateID: state, Nonce: nonce, URL: authorization.URL}, nil
}

// CompleteCallback performs one atomic attempt consumption, one gotth-oidc
// verification/exchange, and one session write. A failed exchange still spends
// the attempt, preventing replay after partial failure.
func CompleteCallback(ctx context.Context, client OIDCClient, store StateStore, input CallbackInput, now time.Time) (CallbackResult, error) {
	if client == nil || store == nil || strings.TrimSpace(input.Response.State) == "" {
		return CallbackResult{}, ErrInvalidOIDCState
	}
	attempt, err := store.ConsumeAttempt(ctx, input.Response.State, input.BrowserBinding, now.UTC())
	if err != nil {
		return CallbackResult{}, err
	}
	verified, err := client.CompleteResponse(ctx, input.Response, attempt.Protected)
	if err != nil {
		return CallbackResult{}, ErrInvalidOIDCToken
	}
	identity := Identity{Issuer: verified.Issuer, Subject: verified.Subject, Name: verified.DisplayName, Groups: []string{}}
	if verified.Email != nil {
		identity.Email = *verified.Email
	}
	sessionID, err := randomToken(32)
	if err != nil {
		return CallbackResult{}, err
	}
	csrfSecret, err := randomToken(32)
	if err != nil {
		return CallbackResult{}, err
	}
	session := Session{
		ID: sessionID, IdentityRefID: identity.Issuer + "|" + identity.Subject,
		CreatedAt: now.UTC(), ExpiresAt: now.UTC().Add(12 * time.Hour), LastSeenAt: now.UTC(),
		CSRFSecretHash: hashText(csrfSecret), AuthMethod: "oidc",
	}
	if err := store.PutSession(ctx, session); err != nil {
		return CallbackResult{}, err
	}
	return CallbackResult{Identity: identity, Session: session, RedirectAfterLogin: attempt.RedirectAfterLogin}, nil
}

func localRedirect(value string) (string, error) {
	if value == "" {
		return "/", nil
	}
	if len(value) > 2048 || !utf8.ValidString(value) || strings.IndexFunc(value, unicode.IsControl) >= 0 {
		return "", ErrInvalidOIDCState
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.IsAbs() || parsed.Host != "" || !strings.HasPrefix(parsed.Path, "/") || strings.HasPrefix(parsed.Path, "//") {
		return "", ErrInvalidOIDCState
	}
	return value, nil
}

func randomToken(size int) (string, error) {
	value := make([]byte, size)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(value), nil
}

func NewBrowserBinding() (string, error) { return randomToken(32) }

func hashText(value string) string {
	digest := sha256.Sum256([]byte(value))
	return base64.RawURLEncoding.EncodeToString(digest[:])
}

func SafeOIDCError(err error) string {
	if err == nil {
		return ""
	}
	switch {
	case errors.Is(err, ErrInvalidOIDCState):
		return ErrInvalidOIDCState.Error()
	case errors.Is(err, ErrInvalidOIDCToken):
		return ErrInvalidOIDCToken.Error()
	default:
		return "OIDC operation failed"
	}
}
