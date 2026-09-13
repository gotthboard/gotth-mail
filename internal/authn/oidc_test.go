package authn

import (
	"context"
	"crypto/sha256"
	"errors"
	"net/url"
	"sync"
	"testing"
	"time"

	gotthoidc "github.com/gotthboard/gotth-oidc/pkg/oidc"
)

func TestOIDCProtectedAttemptCreatesSessionAndRejectsReplay(t *testing.T) {
	now := time.Unix(2_000, 0).UTC()
	client := testOIDCClient("state-1", "nonce-1")
	email := "alice@example.test"
	client.identity = gotthoidc.Identity{Issuer: "https://auth.example.test/", Subject: "user-123", DisplayName: "Alice", Email: &email}
	store := NewStore()
	start, err := StartLogin(context.Background(), client, store, "browser-binding", "/admin", now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if start.StateID != "state-1" || start.Nonce != "nonce-1" {
		t.Fatalf("bad login start %#v", start)
	}
	result, err := CompleteCallback(context.Background(), client, store, CallbackInput{Response: gotthoidc.AuthorizationResponse{State: start.StateID, Code: "code-1"}, BrowserBinding: "browser-binding"}, now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if result.Identity.Subject != "user-123" || result.Identity.Email != email || result.RedirectAfterLogin != "/admin" || len(result.Identity.Groups) != 0 {
		t.Fatalf("bad callback result %#v", result)
	}
	if _, ok := store.Session(context.Background(), result.Session.ID); !ok {
		t.Fatal("session not stored")
	}
	if _, err := CompleteCallback(context.Background(), client, store, CallbackInput{Response: gotthoidc.AuthorizationResponse{State: start.StateID, Code: "code-1"}, BrowserBinding: "browser-binding"}, now.Add(2*time.Second)); err != ErrInvalidOIDCState {
		t.Fatalf("replay error=%v", err)
	}
}

func TestOIDCFailedExchangeSpendsAttempt(t *testing.T) {
	now := time.Unix(3_000, 0).UTC()
	client := testOIDCClient("state-2", "nonce-2")
	client.completeErr = errors.New("provider rejected code")
	store := NewStore()
	start, err := StartLogin(context.Background(), client, store, "browser", "/", now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	input := CallbackInput{Response: gotthoidc.AuthorizationResponse{State: start.StateID, Code: "bad-code"}, BrowserBinding: "browser"}
	if _, err := CompleteCallback(context.Background(), client, store, input, now.Add(time.Second)); err != ErrInvalidOIDCToken {
		t.Fatalf("first error=%v", err)
	}
	client.completeErr = nil
	if _, err := CompleteCallback(context.Background(), client, store, input, now.Add(2*time.Second)); err != ErrInvalidOIDCState {
		t.Fatalf("spent attempt error=%v", err)
	}
}

func TestOIDCRejectsWrongBrowserExpiredAttemptAndExternalReturn(t *testing.T) {
	now := time.Unix(4_000, 0).UTC()
	client := testOIDCClient("state-3", "nonce-3")
	store := NewStore()
	start, err := StartLogin(context.Background(), client, store, "browser", "/inside?x=1", now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := CompleteCallback(context.Background(), client, store, CallbackInput{Response: gotthoidc.AuthorizationResponse{State: start.StateID, Code: "code"}, BrowserBinding: "wrong"}, now.Add(time.Second)); err != ErrInvalidOIDCState {
		t.Fatalf("wrong browser error=%v", err)
	}
	if _, err := CompleteCallback(context.Background(), client, store, CallbackInput{Response: gotthoidc.AuthorizationResponse{State: start.StateID, Code: "code"}, BrowserBinding: "browser"}, now.Add(2*time.Minute)); err != ErrInvalidOIDCState {
		t.Fatalf("expired attempt error=%v", err)
	}
	for _, target := range []string{"https://evil.example/", "//evil.example/", "/ok\nLocation: https://evil.example/"} {
		if _, err := StartLogin(context.Background(), testOIDCClient("another-state", "another-nonce"), NewStore(), "browser", target, now, time.Minute); err != ErrInvalidOIDCState {
			t.Fatalf("external return %q error=%v", target, err)
		}
	}
}

func TestOIDCMemoryStoreAdmitsOneConcurrentCallback(t *testing.T) {
	now := time.Unix(5_000, 0).UTC()
	client := testOIDCClient("state-4", "nonce-4")
	store := NewStore()
	start, err := StartLogin(context.Background(), client, store, "browser", "/", now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	winners := make(chan struct{}, 2)
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := CompleteCallback(context.Background(), client, store, CallbackInput{Response: gotthoidc.AuthorizationResponse{State: start.StateID, Code: "code"}, BrowserBinding: "browser"}, now.Add(time.Second)); err == nil {
				winners <- struct{}{}
			}
		}()
	}
	wg.Wait()
	close(winners)
	if len(winners) != 1 {
		t.Fatalf("concurrent callback winners=%d", len(winners))
	}
}

func TestOIDCSafeErrorsAreFixedAndDoNotEchoProviderText(t *testing.T) {
	if SafeOIDCError(nil) != "" {
		t.Fatal("nil error was not empty")
	}
	if got := SafeOIDCError(ErrInvalidOIDCToken); got != ErrInvalidOIDCToken.Error() {
		t.Fatalf("known error=%q", got)
	}
	if got := SafeOIDCError(errors.New("token=aaa.bbb.ccc")); got != "OIDC operation failed" {
		t.Fatalf("provider text escaped: %q", got)
	}
}

func TestOIDCStartBoundaryFailures(t *testing.T) {
	now := time.Unix(6_000, 0).UTC()
	valid := testOIDCClient("state-5", "nonce-5")
	for name, run := range map[string]func() error{
		"nil client": func() error {
			_, err := StartLogin(context.Background(), nil, NewStore(), "browser", "/", now, time.Minute)
			return err
		},
		"nil store": func() error {
			_, err := StartLogin(context.Background(), valid, nil, "browser", "/", now, time.Minute)
			return err
		},
		"empty browser": func() error {
			_, err := StartLogin(context.Background(), valid, NewStore(), "", "/", now, time.Minute)
			return err
		},
		"oversized browser": func() error {
			_, err := StartLogin(context.Background(), valid, NewStore(), string(make([]byte, 1025)), "/", now, time.Minute)
			return err
		},
		"zero ttl": func() error {
			_, err := StartLogin(context.Background(), valid, NewStore(), "browser", "/", now, 0)
			return err
		},
		"oversized ttl": func() error {
			_, err := StartLogin(context.Background(), valid, NewStore(), "browser", "/", now, time.Hour)
			return err
		},
	} {
		t.Run(name, func(t *testing.T) {
			if err := run(); err == nil {
				t.Fatal("invalid login boundary accepted")
			}
		})
	}
	beginFailure := testOIDCClient("state-6", "nonce-6")
	beginFailure.beginErr = errors.New("entropy failed")
	if _, err := StartLogin(context.Background(), beginFailure, NewStore(), "browser", "/", now, time.Minute); err == nil {
		t.Fatal("begin failure accepted")
	}
	malformed := testOIDCClient("state-7", "nonce-7")
	malformed.authorization.URL = "://bad"
	if _, err := StartLogin(context.Background(), malformed, NewStore(), "browser", "/", now, time.Minute); err == nil {
		t.Fatal("malformed authorization URL accepted")
	}
	inconsistent := testOIDCClient("state-8", "nonce-8")
	inconsistent.authorization.Attempt.StateHash = sha256.Sum256([]byte("different"))
	if _, err := StartLogin(context.Background(), inconsistent, NewStore(), "browser", "/", now, time.Minute); err == nil {
		t.Fatal("inconsistent protected attempt accepted")
	}
	if _, err := StartLogin(context.Background(), valid, errorStateStore{putAttemptErr: errors.New("database down")}, "browser", "/", now, time.Minute); err == nil {
		t.Fatal("store failure accepted")
	}
}

func TestOIDCCompletionBoundaryFailuresAndOptionalEmail(t *testing.T) {
	now := time.Unix(7_000, 0).UTC()
	if _, err := CompleteCallback(context.Background(), nil, NewStore(), CallbackInput{}, now); err != ErrInvalidOIDCState {
		t.Fatalf("nil client error=%v", err)
	}
	client := testOIDCClient("state-9", "nonce-9")
	store := NewStore()
	start, err := StartLogin(context.Background(), client, store, "browser", "/", now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	client.identity.Email = nil
	result, err := CompleteCallback(context.Background(), client, store, CallbackInput{Response: gotthoidc.AuthorizationResponse{State: start.StateID, Code: "code"}, BrowserBinding: "browser"}, now.Add(time.Second))
	if err != nil || result.Identity.Email != "" {
		t.Fatalf("optional email result=%#v err=%v", result, err)
	}
	client = testOIDCClient("state-10", "nonce-10")
	delegate := NewStore()
	start, err = StartLogin(context.Background(), client, delegate, "browser", "/", now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	failing := errorStateStore{StateStore: delegate, putSessionErr: errors.New("database down")}
	if _, err := CompleteCallback(context.Background(), client, failing, CallbackInput{Response: gotthoidc.AuthorizationResponse{State: start.StateID, Code: "code"}, BrowserBinding: "browser"}, now.Add(time.Second)); err == nil {
		t.Fatal("session persistence failure accepted")
	}
}

func TestOIDCZeroValueMemoryStoreAndBrowserBinding(t *testing.T) {
	var store Store
	client := testOIDCClient("state-11", "nonce-11")
	start, err := StartLogin(context.Background(), client, &store, "browser", "/", time.Unix(8_000, 0), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.PutAttempt(context.Background(), LoginAttempt{Protected: client.authorization.Attempt}); err == nil {
		t.Fatalf("duplicate state %q replaced the original attempt", start.StateID)
	}
	binding, err := NewBrowserBinding()
	if err != nil || len(binding) != 43 {
		t.Fatalf("binding length=%d err=%v", len(binding), err)
	}
	var nilStore *Store
	if err := nilStore.PutAttempt(context.Background(), LoginAttempt{}); err == nil {
		t.Fatal("nil memory store accepted write")
	}
	if _, ok := nilStore.Session(context.Background(), "missing"); ok {
		t.Fatal("nil memory store returned session")
	}
	if _, err := nilStore.ConsumeAttempt(context.Background(), "state", "browser", time.Now()); err != ErrInvalidOIDCState {
		t.Fatalf("nil memory consume error=%v", err)
	}
	if err := nilStore.PutSession(context.Background(), Session{}); err == nil {
		t.Fatal("nil memory store accepted session")
	}
}

type fakeOIDCClient struct {
	authorization gotthoidc.Authorization
	identity      gotthoidc.Identity
	beginErr      error
	completeErr   error
}

func testOIDCClient(state, nonce string) *fakeOIDCClient {
	attempt := gotthoidc.ProtectedAttempt{StateHash: sha256.Sum256([]byte(state)), ContextCiphertext: "protected-context"}
	attempt.NonceCiphertext[0] = 1
	attempt.PKCEVerifierCiphertext[0] = 2
	query := url.Values{"state": {state}, "nonce": {nonce}, "code_challenge": {"challenge"}, "code_challenge_method": {"S256"}}
	return &fakeOIDCClient{
		authorization: gotthoidc.Authorization{URL: "https://auth.example.test/authorize?" + query.Encode(), Attempt: attempt},
		identity:      gotthoidc.Identity{Issuer: "https://auth.example.test/", Subject: "subject"},
	}
}

func (f *fakeOIDCClient) Begin() (gotthoidc.Authorization, error) {
	if f.beginErr != nil {
		return gotthoidc.Authorization{}, f.beginErr
	}
	return f.authorization, nil
}

func (f *fakeOIDCClient) CompleteResponse(_ context.Context, response gotthoidc.AuthorizationResponse, attempt gotthoidc.ProtectedAttempt) (gotthoidc.Identity, error) {
	if f.completeErr != nil {
		return gotthoidc.Identity{}, f.completeErr
	}
	if response.State == "" || (response.Code == "" && response.Error == nil) || attempt != f.authorization.Attempt {
		return gotthoidc.Identity{}, errors.New("bad completion input")
	}
	return f.identity, nil
}

type errorStateStore struct {
	StateStore
	putAttemptErr error
	putSessionErr error
}

func (store errorStateStore) PutAttempt(ctx context.Context, attempt LoginAttempt) error {
	if store.putAttemptErr != nil {
		return store.putAttemptErr
	}
	return store.StateStore.PutAttempt(ctx, attempt)
}

func (store errorStateStore) PutSession(ctx context.Context, session Session) error {
	if store.putSessionErr != nil {
		return store.putSessionErr
	}
	return store.StateStore.PutSession(ctx, session)
}
