package authn

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"strings"
	"testing"
	"time"
)

func TestOIDCAuthCodeCallbackValidatesStateTokenAndCreatesSession(t *testing.T) {
	key, jwks := testJWKS(t, "kid1")
	now := time.Unix(2000, 0).UTC()
	cfg := testOIDCConfig(now)
	store := NewStore()
	start, err := StartLogin(cfg, store, "https://auth.example.test/application/o/authorize/", "browser-hash", "/admin", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	tok := signToken(t, key, "kid1", map[string]any{"iss": cfg.Issuer, "sub": "user-123", "aud": []string{cfg.ClientID}, "azp": cfg.ClientID, "exp": now.Add(time.Hour).Unix(), "iat": now.Unix(), "nbf": now.Add(-time.Second).Unix(), "nonce": start.Nonce, "email": "alice@example.test", "name": "Alice"})
	res, err := CompleteCallback(context.Background(), cfg, store, CallbackInput{StateID: start.StateID, BrowserBindingHash: "browser-hash", RedirectURI: cfg.RedirectURI, IDToken: tok, JWKS: jwks})
	if err != nil {
		t.Fatal(err)
	}
	if res.Identity.Subject != "user-123" || res.Identity.Email != "alice@example.test" || res.Session.AuthMethod != "oidc" {
		t.Fatalf("bad result %#v", res)
	}
	if _, ok := store.Session(res.Session.ID); !ok {
		t.Fatal("session not stored")
	}
	if _, err := CompleteCallback(context.Background(), cfg, store, CallbackInput{StateID: start.StateID, BrowserBindingHash: "browser-hash", RedirectURI: cfg.RedirectURI, IDToken: tok, JWKS: jwks}); err != ErrInvalidOIDCState {
		t.Fatalf("reused state err=%v", err)
	}
}

func TestOIDCRejectsInvalidStateNonceRedirectAndUnsignedClaims(t *testing.T) {
	key, jwks := testJWKS(t, "kid1")
	now := time.Unix(3000, 0).UTC()
	cfg := testOIDCConfig(now)
	store := NewStore()
	start, _ := StartLogin(cfg, store, "https://auth.example.test/authorize", "browser", "", time.Minute)
	validClaims := map[string]any{"iss": cfg.Issuer, "sub": "user-123", "aud": cfg.ClientID, "exp": now.Add(time.Hour).Unix(), "iat": now.Unix(), "nonce": start.Nonce}
	valid := signToken(t, key, "kid1", validClaims)
	if _, err := CompleteCallback(context.Background(), cfg, store, CallbackInput{StateID: start.StateID, BrowserBindingHash: "wrong", RedirectURI: cfg.RedirectURI, IDToken: valid, JWKS: jwks}); err != ErrInvalidOIDCState {
		t.Fatalf("wrong browser err=%v", err)
	}
	start, _ = StartLogin(cfg, store, "https://auth.example.test/authorize", "browser", "", time.Minute)
	if _, err := CompleteCallback(context.Background(), cfg, store, CallbackInput{StateID: start.StateID, BrowserBindingHash: "browser", RedirectURI: "https://mail.example.test/wrong", IDToken: valid, JWKS: jwks}); err != ErrInvalidOIDCState {
		t.Fatalf("wrong redirect err=%v", err)
	}
	start, _ = StartLogin(cfg, store, "https://auth.example.test/authorize", "browser", "", time.Minute)
	badNonce := mapClone(validClaims)
	badNonce["nonce"] = "bad"
	if _, err := CompleteCallback(context.Background(), cfg, store, CallbackInput{StateID: start.StateID, BrowserBindingHash: "browser", RedirectURI: cfg.RedirectURI, IDToken: signToken(t, key, "kid1", badNonce), JWKS: jwks}); err != ErrInvalidOIDCToken {
		t.Fatalf("bad nonce err=%v", err)
	}
	unsigned := unsignedToken(t, validClaims)
	if _, err := ValidateIDToken(cfg, unsigned, jwks, start.Nonce); err != ErrInvalidOIDCToken {
		t.Fatalf("unsigned token err=%v", err)
	}
}

func TestOIDCTokenClaimValidationMatrix(t *testing.T) {
	key, jwks := testJWKS(t, "kid1")
	now := time.Unix(4000, 0).UTC()
	cfg := testOIDCConfig(now)
	base := map[string]any{"iss": cfg.Issuer, "sub": "user-123", "aud": []string{"other", cfg.ClientID}, "azp": cfg.ClientID, "exp": now.Add(time.Hour).Unix(), "iat": now.Unix(), "nbf": now.Add(-time.Second).Unix(), "nonce": "n"}
	if _, err := ValidateIDToken(cfg, signToken(t, key, "kid1", base), jwks, "n"); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name   string
		mutate func(map[string]any)
	}{
		{"issuer", func(m map[string]any) { m["iss"] = "https://evil.example.test" }},
		{"subject", func(m map[string]any) { m["sub"] = "" }},
		{"audience", func(m map[string]any) { m["aud"] = "other" }},
		{"azp", func(m map[string]any) { m["azp"] = "other" }},
		{"expired", func(m map[string]any) { m["exp"] = now.Add(-2 * time.Hour).Unix() }},
		{"future_iat", func(m map[string]any) { m["iat"] = now.Add(2 * time.Hour).Unix() }},
		{"future_nbf", func(m map[string]any) { m["nbf"] = now.Add(2 * time.Hour).Unix() }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := mapClone(base)
			tc.mutate(m)
			if _, err := ValidateIDToken(cfg, signToken(t, key, "kid1", m), jwks, "n"); err != ErrInvalidOIDCToken {
				t.Fatalf("err=%v", err)
			}
		})
	}
}

func TestOIDCSafeErrorsDoNotExposeToken(t *testing.T) {
	if got := SafeOIDCError(ErrInvalidOIDCToken); got != ErrInvalidOIDCToken.Error() {
		t.Fatalf("safe err %q", got)
	}
	if got := SafeOIDCError(assertErr("token=aaa.bbb.ccc")); got != ErrUnsafeTokenLogValue.Error() {
		t.Fatalf("unsafe err %q", got)
	}
}

type assertErr string

func (e assertErr) Error() string { return string(e) }

func testOIDCConfig(now time.Time) OIDCConfig {
	return OIDCConfig{Issuer: "https://auth.example.test/application/o/gmf/", ClientID: "gmf", RedirectURI: "https://mail.example.test/api/v1/oidc/callback", ClockSkew: time.Minute, Now: func() time.Time { return now }}
}
func mapClone(in map[string]any) map[string]any {
	out := map[string]any{}
	for k, v := range in {
		out[k] = v
	}
	return out
}
func testJWKS(t *testing.T, kid string) (*rsa.PrivateKey, JWKS) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	e := big.NewInt(int64(key.PublicKey.E)).Bytes()
	return key, JWKS{Keys: []JWK{{Kty: "RSA", Kid: kid, Alg: "RS256", Use: "sig", N: base64.RawURLEncoding.EncodeToString(key.PublicKey.N.Bytes()), E: base64.RawURLEncoding.EncodeToString(e)}}}
}
func signToken(t *testing.T, key *rsa.PrivateKey, kid string, claims map[string]any) string {
	t.Helper()
	header := map[string]any{"alg": "RS256", "kid": kid, "typ": "JWT"}
	h := encJSON(t, header)
	c := encJSON(t, claims)
	signed := []byte(h + "." + c)
	d := sha256.Sum256(signed)
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, d[:])
	if err != nil {
		t.Fatal(err)
	}
	return h + "." + c + "." + base64.RawURLEncoding.EncodeToString(sig)
}
func unsignedToken(t *testing.T, claims map[string]any) string {
	return encJSON(t, map[string]any{"alg": "none", "typ": "JWT"}) + "." + encJSON(t, claims) + "."
}
func encJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
func TestStartLoginURLContainsOIDCParameters(t *testing.T) {
	cfg := testOIDCConfig(time.Unix(1, 0))
	st, err := StartLogin(cfg, NewStore(), "https://auth.example.test/authorize", "browser", "/", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"response_type=code", "client_id=gmf", "state=", "nonce=", "redirect_uri=https%3A%2F%2Fmail.example.test%2Fapi%2Fv1%2Foidc%2Fcallback"} {
		if !strings.Contains(st.URL, want) {
			t.Fatalf("url %q missing %q", st.URL, want)
		}
	}
}

func TestOIDCDiscoveryAndTokenResponseValidation(t *testing.T) {
	cfg := testOIDCConfig(time.Unix(5000, 0))
	d := DiscoveryDocument{Issuer: cfg.Issuer, AuthorizationEndpoint: "https://auth.example.test/authorize", TokenEndpoint: "https://auth.example.test/token", JWKSURI: "https://auth.example.test/jwks", ResponseTypes: []string{"code"}, IDTokenAlgs: []string{"RS256"}}
	if err := ValidateDiscovery(cfg, d); err != nil {
		t.Fatal(err)
	}
	d.Issuer = "https://evil.example.test/"
	if err := ValidateDiscovery(cfg, d); err != ErrInvalidOIDCToken {
		t.Fatalf("bad discovery err=%v", err)
	}
	if err := (TokenResponse{IDToken: unsignedToken(t, map[string]any{"sub": "x"})}).ValidateNoUnsignedFallback(); err != ErrInvalidOIDCToken {
		t.Fatalf("unsigned fallback err=%v", err)
	}
	key, _ := testJWKS(t, "kid1")
	if err := (TokenResponse{IDToken: signToken(t, key, "kid1", map[string]any{"sub": "x"})}).ValidateNoUnsignedFallback(); err != nil {
		t.Fatal(err)
	}
}
