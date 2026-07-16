package authn

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"strings"
	"sync"
	"time"
)

var (
	ErrInvalidOIDCState    = errors.New("invalid oidc state")
	ErrInvalidOIDCToken    = errors.New("invalid oidc token")
	ErrUnsafeTokenLogValue = errors.New("oidc failure must not expose token")
)

type OIDCConfig struct {
	Issuer      string
	ClientID    string
	RedirectURI string
	ClockSkew   time.Duration
	Now         func() time.Time
}

type JWK struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Alg string `json:"alg,omitempty"`
	Use string `json:"use,omitempty"`
	N   string `json:"n"`
	E   string `json:"e"`
}

type JWKS struct {
	Keys []JWK `json:"keys"`
}

type LoginState struct {
	StateID            string
	Nonce              string
	BrowserBindingHash string
	RedirectAfterLogin string
	CreatedAt          time.Time
	ExpiresAt          time.Time
	UsedAt             *time.Time
}

type Identity struct {
	Subject string
	Issuer  string
	Email   string
	Name    string
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

type Store struct {
	mu       sync.Mutex
	states   map[string]LoginState
	sessions map[string]Session
}

func NewStore() *Store {
	return &Store{states: map[string]LoginState{}, sessions: map[string]Session{}}
}

func (s *Store) PutState(st LoginState) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ensure()
	s.states[st.StateID] = st
}
func (s *Store) Session(id string) (Session, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ensure()
	v, ok := s.sessions[id]
	return v, ok
}
func (s *Store) ensure() {
	if s.states == nil {
		s.states = map[string]LoginState{}
	}
	if s.sessions == nil {
		s.sessions = map[string]Session{}
	}
}

func (s *Store) consumeState(stateID, browserHash string, now time.Time) (LoginState, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ensure()
	st, ok := s.states[stateID]
	if !ok || st.BrowserBindingHash != browserHash || !st.UsedAtIsNil() || now.After(st.ExpiresAt) {
		return LoginState{}, ErrInvalidOIDCState
	}
	used := now
	st.UsedAt = &used
	s.states[stateID] = st
	return st, nil
}
func (s *Store) putSession(sess Session) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ensure()
	s.sessions[sess.ID] = sess
}
func (st LoginState) UsedAtIsNil() bool { return st.UsedAt == nil }

type LoginStart struct {
	StateID string
	Nonce   string
	URL     string
}

type CallbackInput struct {
	StateID            string
	BrowserBindingHash string
	RedirectURI        string
	IDToken            string
	JWKS               JWKS
}

type CallbackResult struct {
	Identity Identity
	Session  Session
}

func StartLogin(cfg OIDCConfig, store *Store, authorizeEndpoint, browserBindingHash, redirectAfter string, ttl time.Duration) (LoginStart, error) {
	if store == nil {
		return LoginStart{}, fmt.Errorf("oidc store required")
	}
	if err := cfg.validate(); err != nil {
		return LoginStart{}, err
	}
	if authorizeEndpoint == "" || browserBindingHash == "" {
		return LoginStart{}, fmt.Errorf("authorize endpoint and browser binding required")
	}
	now := cfg.now()
	state := randomToken(32)
	nonce := randomToken(32)
	store.PutState(LoginState{StateID: state, Nonce: nonce, BrowserBindingHash: browserBindingHash, RedirectAfterLogin: redirectAfter, CreatedAt: now, ExpiresAt: now.Add(ttl)})
	u, err := url.Parse(authorizeEndpoint)
	if err != nil {
		return LoginStart{}, err
	}
	q := u.Query()
	q.Set("response_type", "code")
	q.Set("client_id", cfg.ClientID)
	q.Set("redirect_uri", cfg.RedirectURI)
	q.Set("scope", "openid email profile")
	q.Set("state", state)
	q.Set("nonce", nonce)
	u.RawQuery = q.Encode()
	return LoginStart{StateID: state, Nonce: nonce, URL: u.String()}, nil
}

func CompleteCallback(ctx context.Context, cfg OIDCConfig, store *Store, in CallbackInput) (CallbackResult, error) {
	if store == nil {
		return CallbackResult{}, fmt.Errorf("oidc store required")
	}
	if err := cfg.validate(); err != nil {
		return CallbackResult{}, err
	}
	now := cfg.now()
	if in.RedirectURI != cfg.RedirectURI {
		return CallbackResult{}, ErrInvalidOIDCState
	}
	st, err := store.consumeState(in.StateID, in.BrowserBindingHash, now)
	if err != nil {
		return CallbackResult{}, err
	}
	claims, err := ValidateIDToken(cfg, in.IDToken, in.JWKS, st.Nonce)
	if err != nil {
		return CallbackResult{}, err
	}
	identity := Identity{Subject: claims.Subject, Issuer: claims.Issuer, Email: claims.Email, Name: claims.Name}
	sess := Session{ID: randomToken(32), IdentityRefID: identity.Issuer + "|" + identity.Subject, CreatedAt: now, ExpiresAt: now.Add(12 * time.Hour), LastSeenAt: now, CSRFSecretHash: hashText(randomToken(32)), AuthMethod: "oidc"}
	store.putSession(sess)
	return CallbackResult{Identity: identity, Session: sess}, nil
}

type IDTokenClaims struct {
	Issuer    string          `json:"iss"`
	Subject   string          `json:"sub"`
	Audience  json.RawMessage `json:"aud"`
	Azp       string          `json:"azp,omitempty"`
	Expiry    int64           `json:"exp"`
	IssuedAt  int64           `json:"iat"`
	NotBefore int64           `json:"nbf,omitempty"`
	Nonce     string          `json:"nonce"`
	Email     string          `json:"email,omitempty"`
	Name      string          `json:"name,omitempty"`
}

func ValidateIDToken(cfg OIDCConfig, token string, jwks JWKS, expectedNonce string) (IDTokenClaims, error) {
	if err := cfg.validate(); err != nil {
		return IDTokenClaims{}, err
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return IDTokenClaims{}, ErrInvalidOIDCToken
	}
	var hdr struct{ Alg, Kid, Typ string }
	if err := decodeJSON(parts[0], &hdr); err != nil {
		return IDTokenClaims{}, ErrInvalidOIDCToken
	}
	if hdr.Alg != "RS256" || hdr.Kid == "" {
		return IDTokenClaims{}, ErrInvalidOIDCToken
	}
	key, err := jwks.rsaKey(hdr.Kid)
	if err != nil {
		return IDTokenClaims{}, ErrInvalidOIDCToken
	}
	signed := []byte(parts[0] + "." + parts[1])
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return IDTokenClaims{}, ErrInvalidOIDCToken
	}
	digest := sha256.Sum256(signed)
	if err := rsa.VerifyPKCS1v15(key, crypto.SHA256, digest[:], sig); err != nil {
		return IDTokenClaims{}, ErrInvalidOIDCToken
	}
	var claims IDTokenClaims
	if err := decodeJSON(parts[1], &claims); err != nil {
		return IDTokenClaims{}, ErrInvalidOIDCToken
	}
	if err := claims.validate(cfg, expectedNonce); err != nil {
		return IDTokenClaims{}, err
	}
	return claims, nil
}

func (c IDTokenClaims) validate(cfg OIDCConfig, nonce string) error {
	now := cfg.now()
	skew := cfg.ClockSkew
	if skew == 0 {
		skew = time.Minute
	}
	if c.Issuer != cfg.Issuer || c.Subject == "" || c.Nonce != nonce {
		return ErrInvalidOIDCToken
	}
	if !audContains(c.Audience, cfg.ClientID) {
		return ErrInvalidOIDCToken
	}
	if c.Azp != "" && c.Azp != cfg.ClientID {
		return ErrInvalidOIDCToken
	}
	if c.Expiry == 0 || now.After(time.Unix(c.Expiry, 0).Add(skew)) {
		return ErrInvalidOIDCToken
	}
	if c.IssuedAt == 0 || time.Unix(c.IssuedAt, 0).After(now.Add(skew)) {
		return ErrInvalidOIDCToken
	}
	if c.NotBefore != 0 && time.Unix(c.NotBefore, 0).After(now.Add(skew)) {
		return ErrInvalidOIDCToken
	}
	return nil
}

func audContains(raw json.RawMessage, clientID string) bool {
	var one string
	if json.Unmarshal(raw, &one) == nil {
		return one == clientID
	}
	var many []string
	if json.Unmarshal(raw, &many) == nil {
		for _, v := range many {
			if v == clientID {
				return true
			}
		}
	}
	return false
}
func (j JWKS) rsaKey(kid string) (*rsa.PublicKey, error) {
	for _, k := range j.Keys {
		if k.Kid == kid && k.Kty == "RSA" {
			nBytes, err := base64.RawURLEncoding.DecodeString(k.N)
			if err != nil {
				return nil, err
			}
			eBytes, err := base64.RawURLEncoding.DecodeString(k.E)
			if err != nil {
				return nil, err
			}
			e := 0
			for _, b := range eBytes {
				e = e*256 + int(b)
			}
			if e == 0 {
				return nil, errors.New("bad exponent")
			}
			return &rsa.PublicKey{N: new(big.Int).SetBytes(nBytes), E: e}, nil
		}
	}
	return nil, errors.New("kid not found")
}
func decodeJSON(part string, v any) error {
	b, err := base64.RawURLEncoding.DecodeString(part)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}
func (c OIDCConfig) validate() error {
	if c.Issuer == "" || c.ClientID == "" || c.RedirectURI == "" {
		return fmt.Errorf("oidc issuer, client id, and redirect uri required")
	}
	return nil
}
func (c OIDCConfig) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now().UTC()
}
func randomToken(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}
func hashText(s string) string {
	h := sha256.Sum256([]byte(s))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

func SafeOIDCError(err error) string {
	if err == nil {
		return ""
	}
	s := err.Error()
	if strings.Count(s, ".") >= 2 || strings.Contains(strings.ToLower(s), "token=") {
		return ErrUnsafeTokenLogValue.Error()
	}
	return s
}

type DiscoveryDocument struct {
	Issuer                string   `json:"issuer"`
	AuthorizationEndpoint string   `json:"authorization_endpoint"`
	TokenEndpoint         string   `json:"token_endpoint"`
	JWKSURI               string   `json:"jwks_uri"`
	ResponseTypes         []string `json:"response_types_supported"`
	SubjectTypes          []string `json:"subject_types_supported"`
	IDTokenAlgs           []string `json:"id_token_signing_alg_values_supported"`
}

func ValidateDiscovery(cfg OIDCConfig, d DiscoveryDocument) error {
	if err := cfg.validate(); err != nil {
		return err
	}
	if d.Issuer != cfg.Issuer || d.AuthorizationEndpoint == "" || d.TokenEndpoint == "" || d.JWKSURI == "" {
		return ErrInvalidOIDCToken
	}
	if !contains(d.ResponseTypes, "code") || !contains(d.IDTokenAlgs, "RS256") {
		return ErrInvalidOIDCToken
	}
	return nil
}

type TokenResponse struct {
	IDToken     string `json:"id_token"`
	AccessToken string `json:"access_token,omitempty"`
	TokenType   string `json:"token_type,omitempty"`
	ExpiresIn   int64  `json:"expires_in,omitempty"`
}

func (tr TokenResponse) ValidateNoUnsignedFallback() error {
	if strings.TrimSpace(tr.IDToken) == "" {
		return ErrInvalidOIDCToken
	}
	parts := strings.Split(tr.IDToken, ".")
	if len(parts) != 3 {
		return ErrInvalidOIDCToken
	}
	var hdr struct {
		Alg string `json:"alg"`
	}
	if err := decodeJSON(parts[0], &hdr); err != nil || hdr.Alg == "" || strings.EqualFold(hdr.Alg, "none") {
		return ErrInvalidOIDCToken
	}
	return nil
}

func contains(xs []string, want string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}
