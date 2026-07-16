package webmail

import (
	"context"
	"errors"
	"fmt"
	"html"
	"mime/multipart"
	"net/mail"
	"regexp"
	"sort"
	"strings"
	"time"

	"forgejo/linus/gophermailforge/internal/audit"
)

type Message struct {
	ID, Folder, From, To, Subject, BodyHTML, BodyText string
	Date                                              time.Time
	Flags                                             []string
	Attachments                                       []Attachment
}
type Attachment struct {
	Filename, ContentType string
	Size                  int64
	Content               []byte
}
type MessageSummary struct {
	ID, From, Subject, Date string
	Flags                   []string
}
type ListResult struct {
	Folder, Cursor, NextCursor string
	Messages                   []MessageSummary
}

type IMAPClient interface {
	ListFolders(context.Context, string) ([]string, error)
	ListMessages(context.Context, string, string, int) ([]Message, error)
	ReadMessage(context.Context, string, string) (Message, error)
	Search(context.Context, string, string, int) ([]Message, error)
	Quota(context.Context) (int64, int64, error)
}
type SMTPSubmitter interface {
	Submit(context.Context, Envelope, []byte) error
}
type OpenPGPSigner interface {
	SignMIME(context.Context, Identity, []byte) ([]byte, SignatureStatus, error)
}
type Identity struct{ Address, Fingerprint string }
type SignatureStatus struct {
	Fingerprint, Identity string
	Signed                bool
}
type Envelope struct {
	From string
	To   []string
}

type Client struct {
	IMAP                   IMAPClient
	ExternalProviderUsable bool
}

func (c Client) FolderList(ctx context.Context, user string) ([]string, error) {
	if c.IMAP == nil {
		return nil, errors.New("imap client required")
	}
	fs, err := c.IMAP.ListFolders(ctx, user)
	sort.Strings(fs)
	return fs, err
}
func (c Client) Quota(ctx context.Context) (int64, int64, error) {
	if c.IMAP == nil {
		return 0, 0, errors.New("imap client required")
	}
	return c.IMAP.Quota(ctx)
}
func (c Client) List(ctx context.Context, folder, cursor string, limit int) (ListResult, error) {
	if c.IMAP == nil {
		return ListResult{}, errors.New("imap client required")
	}
	if limit <= 0 || limit > 100 {
		limit = 50
	}
	msgs, err := c.IMAP.ListMessages(ctx, folder, cursor, limit)
	if err != nil {
		return ListResult{}, err
	}
	out := ListResult{Folder: folder, Cursor: cursor}
	for _, m := range msgs {
		out.Messages = append(out.Messages, MessageSummary{ID: m.ID, From: html.EscapeString(m.From), Subject: html.EscapeString(m.Subject), Date: m.Date.Format(time.RFC3339), Flags: append([]string(nil), m.Flags...)})
	}
	if len(msgs) == limit {
		out.NextCursor = msgs[len(msgs)-1].ID
	}
	return out, nil
}
func (c Client) Read(ctx context.Context, folder, id string) (Message, error) {
	if c.IMAP == nil {
		return Message{}, errors.New("imap client required")
	}
	m, err := c.IMAP.ReadMessage(ctx, folder, id)
	if err != nil {
		return Message{}, err
	}
	m.From = html.EscapeString(m.From)
	m.Subject = html.EscapeString(m.Subject)
	m.BodyHTML = SanitizeHTML(m.BodyHTML)
	for i, a := range m.Attachments {
		m.Attachments[i] = SafeAttachment(a)
	}
	return m, nil
}
func (c Client) Search(ctx context.Context, folder, query, cursor string, limit int) (ListResult, error) {
	if c.IMAP == nil {
		return ListResult{}, errors.New("imap client required")
	}
	if limit <= 0 || limit > 100 {
		limit = 50
	}
	msgs, err := c.IMAP.Search(ctx, folder, query, 0)
	if err != nil {
		return ListResult{}, err
	}
	start := 0
	if cursor != "" {
		found := false
		for i, m := range msgs {
			if m.ID == cursor {
				start = i + 1
				found = true
				break
			}
		}
		if !found {
			return ListResult{}, errors.New("search cursor not found")
		}
	}
	end := start + limit
	if end > len(msgs) {
		end = len(msgs)
	}
	out := ListResult{Folder: folder, Cursor: cursor}
	for _, m := range msgs[start:end] {
		out.Messages = append(out.Messages, MessageSummary{ID: m.ID, From: html.EscapeString(m.From), Subject: html.EscapeString(m.Subject), Date: m.Date.Format(time.RFC3339), Flags: append([]string(nil), m.Flags...)})
	}
	if end < len(msgs) {
		out.NextCursor = msgs[end-1].ID
	}
	return out, nil
}

type Draft struct {
	ID, From, To, Subject, Body string
	Attachments                 []Attachment
	State                       string
	ReplyTo, ForwardOf          string
	SigningFingerprint          string
}
type Sender struct {
	Drafts map[string]Draft
	SMTP   SMTPSubmitter
	Signer OpenPGPSigner
	Audit  audit.Writer
}

func (s *Sender) SaveDraft(d Draft) Draft {
	if s.Drafts == nil {
		s.Drafts = map[string]Draft{}
	}
	if d.ID == "" {
		d.ID = "draft-" + strings.ReplaceAll(d.To, "@", "-")
	}
	d.State = "draft"
	s.Drafts[d.ID] = d
	return d
}
func (s *Sender) Reply(orig Message, from, body string) Draft {
	return s.SaveDraft(Draft{From: from, To: orig.From, Subject: "Re: " + orig.Subject, Body: body, ReplyTo: orig.ID})
}
func (s *Sender) Forward(orig Message, from, to string) Draft {
	return s.SaveDraft(Draft{From: from, To: to, Subject: "Fwd: " + orig.Subject, Body: orig.BodyText, ForwardOf: orig.ID, Attachments: orig.Attachments})
}
func (s *Sender) Submit(ctx context.Context, id string) (Draft, error) {
	d, ok := s.Drafts[id]
	if !ok {
		return Draft{}, errors.New("draft not found")
	}
	if s.SMTP == nil {
		return Draft{}, errors.New("smtp submitter required")
	}
	if s.Signer == nil {
		return Draft{}, errors.New("openpgp signer required")
	}
	if _, err := mail.ParseAddress(d.To); err != nil {
		return Draft{}, errors.New("invalid recipient")
	}
	if d.SigningFingerprint == "" {
		s.audit(ctx, d, "failure", "openpgp signing identity required", SignatureStatus{})
		d.State = "failed"
		s.Drafts[id] = d
		return d, errors.New("OpenPGP signing identity required")
	}
	d.State = "queued_for_submission"
	s.Drafts[id] = d
	mime, err := BuildMIME(d)
	if err != nil {
		d.State = "failed"
		s.Drafts[id] = d
		return d, err
	}
	signed, status, err := s.Signer.SignMIME(ctx, Identity{Address: d.From, Fingerprint: d.SigningFingerprint}, mime)
	if err != nil || !status.Signed || status.Identity != d.From || status.Fingerprint != d.SigningFingerprint {
		s.audit(ctx, d, "failure", "openpgp signing identity invalid", status)
		d.State = "failed"
		s.Drafts[id] = d
		if err != nil {
			return d, err
		}
		return d, errors.New("OpenPGP signing identity invalid")
	}
	d.State = "submitted"
	s.Drafts[id] = d
	if err := ValidateOpenPGPMIME(signed); err != nil {
		s.audit(ctx, d, "failure", err.Error(), status)
		d.State = "failed"
		s.Drafts[id] = d
		return d, err
	}
	if err := s.SMTP.Submit(ctx, Envelope{From: d.From, To: []string{d.To}}, signed); err != nil {
		s.audit(ctx, d, "failure", err.Error(), status)
		d.State = "failed"
		s.Drafts[id] = d
		return d, err
	}
	d.State = "sent"
	s.Drafts[id] = d
	s.audit(ctx, d, "success", "", status)
	return d, nil
}
func (s *Sender) audit(ctx context.Context, d Draft, result, code string, status SignatureStatus) {
	if s.Audit != nil {
		_ = s.Audit.Write(ctx, audit.Event{Actor: audit.ActorRef{Type: "webmail", ID: d.From}, Action: "webmail.submit", Resource: audit.ResourceRef{Type: "draft", ID: d.ID}, Result: result, ErrorCode: code, AfterRedacted: map[string]any{"openpgp_fingerprint": status.Fingerprint, "signed": status.Signed}})
	}
}
func BuildMIME(d Draft) ([]byte, error) {
	var b strings.Builder
	mw := multipart.NewWriter(&b)
	b.WriteString("Content-Type: multipart/mixed; boundary=" + mw.Boundary() + "\r\nSubject: " + d.Subject + "\r\n\r\n")
	part, err := mw.CreatePart(map[string][]string{"Content-Type": {"text/plain; charset=utf-8"}})
	if err != nil {
		return nil, err
	}
	_, _ = part.Write([]byte(d.Body))
	for _, a := range d.Attachments {
		a = SafeAttachment(a)
		part, err = mw.CreatePart(map[string][]string{"Content-Disposition": {fmt.Sprintf(`attachment; filename="%s"`, a.Filename)}, "Content-Type": {a.ContentType}})
		if err != nil {
			return nil, err
		}
		_, _ = part.Write(a.Content)
	}
	_ = mw.Close()
	return []byte(b.String()), nil
}

func SanitizeHTML(in string) string {
	out := in
	for _, tag := range []string{"script", "style", "iframe", "object", "embed", "base", "form"} {
		re := regexp.MustCompile(`(?is)<` + tag + `.*?>.*?</` + tag + `>`)
		out = re.ReplaceAllString(out, "")
	}
	re := regexp.MustCompile(`(?i)\s+on[a-z]+\s*=`)
	out = re.ReplaceAllString(out, " data-blocked=")
	re = regexp.MustCompile(`(?i)href=["']\s*javascript:[^"']*["']`)
	out = re.ReplaceAllString(out, `href="#blocked"`)
	re = regexp.MustCompile(`(?i)<img[^>]+src=["']https?://[^"']+["'][^>]*>`)
	out = re.ReplaceAllString(out, `<span data-remote-image-blocked="true"></span>`)
	return out
}
func CSP() string {
	return "default-src 'none'; img-src 'self' data:; style-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
}
func SafeAttachment(a Attachment) Attachment {
	re := regexp.MustCompile(`[\x00-\x1f\x7f"\r\n]`)
	a.Filename = re.ReplaceAllString(a.Filename, "_")
	a.Filename = strings.ReplaceAll(a.Filename, "/", "_")
	a.Filename = strings.ReplaceAll(a.Filename, "..", "_")
	if strings.TrimSpace(a.Filename) == "" {
		a.Filename = "attachment"
	}
	if a.Size > 25<<20 {
		a.ContentType = "application/octet-stream"
		a.Content = nil
	}
	return a
}

func ValidateOpenPGPMIME(b []byte) error {
	s := string(b)
	if !strings.Contains(strings.ToLower(s), "multipart/signed") || !strings.Contains(strings.ToLower(s), "protocol=application/pgp-signature") || !strings.Contains(strings.ToLower(s), "micalg=") || !strings.Contains(strings.ToLower(s), "application/pgp-signature") {
		return errors.New("invalid OpenPGP/MIME structure")
	}
	return nil
}
