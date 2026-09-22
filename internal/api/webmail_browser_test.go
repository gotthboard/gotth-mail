package api

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net"
	"net/http"
	"os"
	"testing"
	"time"

	"forgejo/gotthboard/gotth-mail/internal/audit"
	"forgejo/gotthboard/gotth-mail/internal/authn"
	"forgejo/gotthboard/gotth-mail/internal/authz"
	"forgejo/gotthboard/gotth-mail/internal/identity"
	"forgejo/gotthboard/gotth-mail/internal/webmail"
)

type browserSessionStore struct {
	bound authn.BoundSession
}

func (browserSessionStore) PutAttempt(context.Context, authn.LoginAttempt) error { return nil }
func (browserSessionStore) ConsumeAttempt(context.Context, string, string, time.Time) (authn.LoginAttempt, error) {
	return authn.LoginAttempt{}, errors.New("not available in browser fixture")
}
func (browserSessionStore) PutSession(context.Context, authn.Session) error { return nil }
func (s browserSessionStore) Session(_ context.Context, id string) (authn.Session, bool) {
	return s.bound.Session, id == s.bound.ID
}
func (browserSessionStore) PutIdentitySession(context.Context, authn.Identity, authn.Session) (authn.Session, error) {
	return authn.Session{}, errors.New("not available in browser fixture")
}
func (s browserSessionStore) BoundSession(_ context.Context, id string, now time.Time) (authn.BoundSession, bool) {
	return s.bound, id == s.bound.ID && now.Before(s.bound.ExpiresAt)
}

func TestWebmailBrowserFixture(t *testing.T) {
	addr := os.Getenv("GOTTH_MAIL_BROWSER_FIXTURE_ADDR")
	if addr == "" {
		t.Skip("GOTTH_MAIL_BROWSER_FIXTURE_ADDR not set")
	}
	csrf := "browser-csrf-proof"
	digest := sha256.Sum256([]byte(csrf))
	now := time.Now().UTC()
	sessions := browserSessionStore{bound: authn.BoundSession{
		Session: authn.Session{ID: "browser-session", IdentityRefID: "browser-identity", CSRFSecretHash: base64.RawURLEncoding.EncodeToString(digest[:]), CreatedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour)},
		Mailbox: "browser@example.test", Issuer: "https://auth.example.test/", Subject: "browser-subject",
	}}
	ids := identity.NewService("example.test")
	client := &webmail.Client{IMAP: apiFakeIMAP{messages: []webmail.Message{{
		ID: "1", Folder: "INBOX", From: "Sender <sender@example.test>", To: "browser@example.test", Cc: "colleague@example.test", Subject: "Browser smoke message", BodyText: "Safe browser message body; literal onclick= remains ordinary text", Date: now, Flags: []string{},
		Attachments: []webmail.Attachment{{Filename: "proof.txt", ContentType: "text/plain", Size: 5, Content: []byte("proof")}},
	}}}}
	smtp := &apiFakeSMTP{}
	sender := &webmail.Sender{Drafts: map[string]webmail.Draft{}, SMTP: smtp, Signer: apiFakeSigner{}, Resolver: apiFakeResolver{}, Policy: apiFakeOutboundPolicy{}, Audit: &audit.MemoryWriter{}}
	app := Server{Identity: ids, Authz: authz.StaticAuthorizer{}, OIDCStore: sessions, OIDCNow: func() time.Time { return now }, WebmailClient: client, WebmailSender: sender}.Handler()
	done := make(chan struct{}, 1)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/__browser_start":
			http.SetCookie(w, &http.Cookie{Name: "gotth_mail_session", Value: "browser-session", Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode})
			http.SetCookie(w, &http.Cookie{Name: "gotth_mail_csrf", Value: csrf, Path: "/", SameSite: http.SameSiteStrictMode})
			http.Redirect(w, r, "/webmail", http.StatusFound)
		case "/__browser_done":
			select {
			case done <- struct{}{}:
			default:
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			app.ServeHTTP(w, r)
		}
	})
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: handler, ReadHeaderTimeout: 5 * time.Second}
	serveErr := make(chan error, 1)
	go func() { serveErr <- server.Serve(listener) }()
	select {
	case <-done:
	case err := <-serveErr:
		if !errors.Is(err, http.ErrServerClosed) {
			t.Fatal(err)
		}
	case <-time.After(45 * time.Second):
		t.Fatal("browser fixture timed out")
	}
	shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := server.Shutdown(shutdown); err != nil {
		t.Fatal(err)
	}
	if !smtp.sent {
		t.Fatal("browser smoke did not submit composed message")
	}
}
