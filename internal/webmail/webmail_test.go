package webmail

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"forgejo/gotthboard/gotth-mail/internal/audit"
	"forgejo/gotthboard/gotth-mail/internal/outboundpolicy"
)

type fakeIMAP struct {
	folders  []string
	messages []Message
	searched bool
}

func (f *fakeIMAP) ListFolders(context.Context, string) ([]string, error) {
	return append([]string(nil), f.folders...), nil
}
func (f *fakeIMAP) ListMessages(ctx context.Context, user, folder, cursor string, limit int) ([]Message, error) {
	if limit > len(f.messages) {
		limit = len(f.messages)
	}
	return f.messages[:limit], nil
}
func (f *fakeIMAP) ReadMessage(ctx context.Context, user, folder, id string) (Message, error) {
	for _, m := range f.messages {
		if m.ID == id {
			return m, nil
		}
	}
	return Message{}, errors.New("missing")
}
func (f *fakeIMAP) Search(ctx context.Context, user, folder, query, cursor string, limit int) ([]Message, error) {
	f.searched = true
	var out []Message
	start := cursor == ""
	foundCursor := cursor == ""
	for _, m := range f.messages {
		if !start {
			if m.ID == cursor {
				start = true
				foundCursor = true
			}
			continue
		}
		if strings.Contains(strings.ToLower(m.Subject+m.BodyText), strings.ToLower(query)) {
			out = append(out, m)
		}
	}
	if !foundCursor {
		return nil, errors.New("search cursor not found")
	}
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}
func (f *fakeIMAP) Quota(context.Context) (int64, int64, error) { return 1, 10, nil }

type fakeSMTP struct {
	submitted bool
	body      []byte
}

func (f *fakeSMTP) Submit(ctx context.Context, e Envelope, b []byte) error {
	f.submitted = true
	f.body = b
	return nil
}

type fakeSigner struct{ fail bool }

type fakeResolver struct{}

type fakeOutboundPolicy struct {
	decision outboundpolicy.Decision
	err      error
}

func (f fakeOutboundPolicy) Decide(context.Context, string, outboundpolicy.EnforcementRequest) (outboundpolicy.Decision, error) {
	if f.decision.Action == "" {
		f.decision = outboundpolicy.Decision{Action: outboundpolicy.ActionOK, Reason: outboundpolicy.ReasonUnrestricted}
	}
	return f.decision, f.err
}

func (fakeResolver) ResolveSender(ctx context.Context, fp, from, sender string) (Identity, error) {
	if fp == "bad" {
		return Identity{}, errors.New("mismatched_from")
	}
	return Identity{Address: from, Fingerprint: fp}, nil
}

func (f fakeSigner) SignMIME(ctx context.Context, id Identity, b []byte) ([]byte, SignatureStatus, error) {
	if f.fail {
		return nil, SignatureStatus{}, errors.New("sign fail")
	}
	return append([]byte("From: "+id.Address+"\r\nMIME-Version: 1.0\r\nContent-Type: multipart/signed; protocol=\"application/pgp-signature\"; micalg=pgp-sha256; boundary=\"sig\"\r\n\r\n--sig\r\nContent-Type: multipart/mixed; boundary=\"fake\"\r\nX-GOTTH-Mail-Signed-From: "+id.Address+"\r\nX-GOTTH-Mail-Signing-Fingerprint: "+id.Fingerprint+"\r\n\r\n"), append(b, []byte("\r\n--sig\r\nContent-Type: application/pgp-signature\r\n\r\n-----BEGIN PGP SIGNATURE-----\r\n\r\nfake-signature\r\n-----END PGP SIGNATURE-----\r\n--sig--\r\n")...)...), SignatureStatus{Fingerprint: id.Fingerprint, Identity: id.Address, Signed: true}, nil
}

func fixtureClient() (*Client, *fakeIMAP) {
	im := &fakeIMAP{folders: []string{"INBOX"}, messages: []Message{{ID: "1", Folder: "INBOX", From: "a@example.test", Subject: "Hello <x>", BodyHTML: `<b ok onclick="x">hi</b><script>bad()</script><img src="https://evil/x">`, BodyText: "hello body", Date: time.Unix(1, 0), Attachments: []Attachment{{Filename: "../x.txt", ContentType: "text/plain", Size: 1, Content: []byte("x")}}}, {ID: "2", Folder: "INBOX", From: "b@example.test", Subject: "Other", BodyText: "search term", Date: time.Unix(2, 0)}}}
	return &Client{ExternalProviderUsable: true, IMAP: im}, im
}
func TestIMAPFolderListReadPaginationQuotaSearch(t *testing.T) {
	c, im := fixtureClient()
	if !c.ExternalProviderUsable {
		t.Fatal("external provider continuity broken")
	}
	got, err := c.FolderList(context.Background(), "u@example.test")
	if err != nil || len(got) != 1 || got[0] != "INBOX" {
		t.Fatalf("folders=%#v err=%v", got, err)
	}
	used, limit, err := c.Quota(context.Background())
	if err != nil || used != 1 || limit != 10 {
		t.Fatalf("quota %d/%d %v", used, limit, err)
	}
	l, err := c.List(context.Background(), "u@example.test", "INBOX", "", 1)
	if err != nil || len(l.Messages) != 1 || l.NextCursor == "" {
		t.Fatalf("list=%#v err=%v", l, err)
	}
	m, err := c.Read(context.Background(), "u@example.test", "INBOX", "1")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(m.BodyHTML, "script") || strings.Contains(m.BodyHTML, "https://evil") || m.Attachments[0].Filename == "../x.txt" {
		t.Fatalf("unsafe read %#v", m)
	}
	s, err := c.Search(context.Background(), "u@example.test", "INBOX", "term", "", 10)
	if err != nil || len(s.Messages) != 1 || s.Messages[0].ID != "2" || !im.searched {
		t.Fatalf("search=%#v err=%v", s, err)
	}
}
func TestComposeDraftSubmitRequiresOpenPGPMIMEAndSMTP(t *testing.T) {
	w := &audit.MemoryWriter{}
	smtp := &fakeSMTP{}
	s := &Sender{Audit: w, SMTP: smtp, Signer: fakeSigner{}, Resolver: fakeResolver{}, Policy: fakeOutboundPolicy{}, Drafts: map[string]Draft{}}
	d := s.SaveDraft(Draft{From: "u@example.test", To: "r@example.test", Subject: "s", Body: "body"})
	if _, err := s.Submit(context.Background(), d.ID); err == nil {
		t.Fatal("unsigned send accepted")
	}
	d.SigningFingerprint = "fp"
	d.Attachments = []Attachment{{Filename: "file.txt", ContentType: "text/plain"}}
	s.Drafts[d.ID] = d
	sent, err := s.Submit(context.Background(), d.ID)
	if err != nil {
		t.Fatal(err)
	}
	if sent.State != "sent" || !smtp.submitted || !strings.Contains(string(smtp.body), "multipart/signed") || !strings.Contains(string(smtp.body), "application/pgp-signature") || !strings.Contains(string(smtp.body), "multipart/mixed") {
		t.Fatalf("sent=%#v smtp=%s", sent, string(smtp.body))
	}
	if len(w.Events) != 2 || w.Events[1].Result != "success" {
		t.Fatalf("events=%#v", w.Events)
	}
}
func TestReplyForwardAndSendFailure(t *testing.T) {
	smtp := &fakeSMTP{}
	s := &Sender{SMTP: smtp, Signer: fakeSigner{fail: true}, Resolver: fakeResolver{}, Policy: fakeOutboundPolicy{}, Drafts: map[string]Draft{}}
	r := s.Reply(Message{ID: "m1", From: "a@example.test", Subject: "Hi"}, "u@example.test", "reply")
	if r.ReplyTo != "m1" || !strings.HasPrefix(r.Subject, "Re:") {
		t.Fatalf("reply=%#v", r)
	}
	f := s.Forward(Message{ID: "m2", Subject: "Hi", BodyText: "body", Attachments: []Attachment{{Filename: "x"}}}, "u@example.test", "b@example.test")
	if f.ForwardOf != "m2" || len(f.Attachments) != 1 {
		t.Fatalf("fwd=%#v", f)
	}
	f.SigningFingerprint = "fp"
	s.Drafts[f.ID] = f
	if _, err := s.Submit(context.Background(), f.ID); err == nil {
		t.Fatal("sign failure accepted")
	}
	if smtp.submitted {
		t.Fatal("submitted after signing failure")
	}
}

func TestComposeDraftPolicyRejectsAtomicallyBeforeSigningOrSMTP(t *testing.T) {
	smtp := &fakeSMTP{}
	s := &Sender{
		SMTP: smtp, Signer: fakeSigner{}, Resolver: fakeResolver{},
		Policy: fakeOutboundPolicy{decision: outboundpolicy.Decision{Action: outboundpolicy.ActionReject, Reason: outboundpolicy.ReasonRecipientForbidden}},
		Drafts: map[string]Draft{},
	}
	draft := s.SaveDraft(Draft{From: "u@example.test", To: "outside@example.net", Subject: "s", Body: "body", SigningFingerprint: "fp"})
	result, err := s.Submit(context.Background(), draft.ID)
	if err == nil || result.State != "failed" || smtp.submitted {
		t.Fatalf("result=%+v err=%v smtp=%v", result, err, smtp.submitted)
	}
}
func TestSecurityPolicy(t *testing.T) {
	if !strings.Contains(CSP(), "default-src 'none'") {
		t.Fatal(CSP())
	}
	html := SanitizeHTML(`<a onclick="x" href="javascript:bad">x</a><script>x</script><iframe>x</iframe>`)
	if strings.Contains(html, "script") || strings.Contains(html, "onclick=") || strings.Contains(html, "javascript:") || strings.Contains(html, "iframe") {
		t.Fatalf("html=%s", html)
	}
}

func TestAttachmentContentAndFilenameSafety(t *testing.T) {
	a := SafeAttachment(Attachment{Filename: "..\r\n/evil\".txt", ContentType: "text/plain", Size: 1, Content: []byte("payload")})
	if strings.ContainsAny(a.Filename, "\r\n/\"") || strings.Contains(a.Filename, "..") {
		t.Fatalf("filename=%q", a.Filename)
	}
	d := Draft{From: "u@example.test", To: "r@example.test", Subject: "s", Body: "b", Attachments: []Attachment{a}}
	m, err := BuildMIME(d)
	if err != nil || !strings.Contains(string(m), "payload") {
		t.Fatalf("mime=%s err=%v", string(m), err)
	}
}

func TestBuildMIMECanonicalizesTextBodyToCRLF(t *testing.T) {
	m, err := BuildMIME(Draft{From: "u@example.test", To: "r@example.test", Subject: "s", Body: "one\ntwo\rthree\r\nfour", MessageID: "<canonical@example.test>", Date: time.Unix(1700000000, 0)})
	if err != nil {
		t.Fatal(err)
	}
	for i, b := range m {
		if b == '\n' && (i == 0 || m[i-1] != '\r') {
			t.Fatalf("bare LF at byte %d in MIME", i)
		}
	}
	if !strings.Contains(string(m), "one\r\ntwo\r\nthree\r\nfour") {
		t.Fatalf("body was not canonicalized: %q", m)
	}
}

func TestBuildMIMEEncodesUnicodeForSevenBitSMTP(t *testing.T) {
	m, err := BuildMIME(Draft{From: "u@example.test", To: "r@example.test", Subject: "café failed", Body: "résumé ⚠", MessageID: "<unicode@example.test>", Date: time.Unix(1700000000, 0)})
	if err != nil {
		t.Fatal(err)
	}
	for i, b := range m {
		if b > 0x7f {
			t.Fatalf("raw 8-bit byte %#x at offset %d in seven-bit MIME", b, i)
		}
	}
	s := string(m)
	if !strings.Contains(s, "Subject: =?utf-8?q?") || !strings.Contains(s, "Content-Transfer-Encoding: quoted-printable") || !strings.Contains(s, "r=C3=A9sum=C3=A9 =E2=9A=A0") {
		t.Fatalf("unicode MIME was not encoded for seven-bit SMTP:\n%s", s)
	}
}

func TestBuildMIMERejectsInvalidUTF8AndControlBytes(t *testing.T) {
	for _, draft := range []Draft{
		{From: "u@example.test", To: "r@example.test", Subject: string([]byte{0xff}), Body: "body"},
		{From: "u@example.test", To: "r@example.test", Subject: "ok", Body: string([]byte{0xff})},
		{From: "u@example.test", To: "r@example.test", Subject: "bad\x00subject", Body: "body"},
		{From: "u@example.test", To: "r@example.test", Subject: "ok", Body: "bad\x00body"},
		{From: "tést@example.test", To: "r@example.test", Subject: "ok", Body: "body"},
		{From: "u@example.test", To: "tést@example.test", Subject: "ok", Body: "body"},
	} {
		if _, err := BuildMIME(draft); err == nil {
			t.Fatalf("invalid draft accepted: %#v", draft)
		}
	}
}

func TestOpenPGPMIMEStructureRequired(t *testing.T) {
	if err := ValidateOpenPGPMIME([]byte("not signed")); err == nil {
		t.Fatal("accepted non OpenPGP/MIME")
	}
}

func TestDraftIDsDoNotCollide(t *testing.T) {
	s := &Sender{Drafts: map[string]Draft{}}
	a := s.SaveDraft(Draft{To: "same@example.test"})
	b := s.SaveDraft(Draft{To: "same@example.test"})
	if a.ID == b.ID || len(s.Drafts) != 2 {
		t.Fatalf("draft collision a=%q b=%q len=%d", a.ID, b.ID, len(s.Drafts))
	}
}

func TestSearchCursorBeyondFirstWindow(t *testing.T) {
	im := &fakeIMAP{messages: []Message{{ID: "1", Subject: "term"}, {ID: "2", Subject: "term"}, {ID: "3", Subject: "term"}}}
	c := Client{IMAP: im}
	first, err := c.Search(context.Background(), "u@example.test", "INBOX", "term", "", 1)
	if err != nil || first.NextCursor != "1" {
		t.Fatalf("first=%#v err=%v", first, err)
	}
	second, err := c.Search(context.Background(), "u@example.test", "INBOX", "term", first.NextCursor, 1)
	if err != nil || len(second.Messages) != 1 || second.Messages[0].ID != "2" || second.NextCursor != "2" {
		t.Fatalf("second=%#v err=%v", second, err)
	}
	third, err := c.Search(context.Background(), "u@example.test", "INBOX", "term", second.NextCursor, 1)
	if err != nil || len(third.Messages) != 1 || third.Messages[0].ID != "3" || third.NextCursor != "" {
		t.Fatalf("third=%#v err=%v", third, err)
	}
	if _, err := c.Search(context.Background(), "u@example.test", "INBOX", "term", "missing", 1); err == nil {
		t.Fatal("missing cursor accepted")
	}
}
