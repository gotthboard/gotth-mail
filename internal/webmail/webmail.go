package webmail

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"html"
	"mime"
	"mime/multipart"
	"net/mail"
	"net/textproto"
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
	ListMessages(context.Context, string, string, string, int) ([]Message, error)
	ReadMessage(context.Context, string, string, string) (Message, error)
	Search(context.Context, string, string, string, string, int) ([]Message, error)
	Quota(context.Context) (int64, int64, error)
}
type SMTPSubmitter interface {
	Submit(context.Context, Envelope, []byte) error
}
type OpenPGPSigner interface {
	SignMIME(context.Context, Identity, []byte) ([]byte, SignatureStatus, error)
}
type SenderIdentityResolver interface {
	ResolveSender(context.Context, string, string, string) (Identity, error)
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
func (c Client) List(ctx context.Context, user, folder, cursor string, limit int) (ListResult, error) {
	if c.IMAP == nil {
		return ListResult{}, errors.New("imap client required")
	}
	if limit <= 0 || limit > 100 {
		limit = 50
	}
	msgs, err := c.IMAP.ListMessages(ctx, user, folder, cursor, limit)
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
func (c Client) Read(ctx context.Context, user, folder, id string) (Message, error) {
	if c.IMAP == nil {
		return Message{}, errors.New("imap client required")
	}
	m, err := c.IMAP.ReadMessage(ctx, user, folder, id)
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
func (c Client) Search(ctx context.Context, user, folder, query, cursor string, limit int) (ListResult, error) {
	if c.IMAP == nil {
		return ListResult{}, errors.New("imap client required")
	}
	if limit <= 0 || limit > 100 {
		limit = 50
	}
	msgs, err := c.IMAP.Search(ctx, user, folder, query, cursor, limit+1)
	if err != nil {
		return ListResult{}, err
	}
	hadMore := len(msgs) > limit
	if hadMore {
		msgs = msgs[:limit]
	}
	out := ListResult{Folder: folder, Cursor: cursor}
	for _, m := range msgs {
		out.Messages = append(out.Messages, MessageSummary{ID: m.ID, From: html.EscapeString(m.From), Subject: html.EscapeString(m.Subject), Date: m.Date.Format(time.RFC3339), Flags: append([]string(nil), m.Flags...)})
	}
	if hadMore && len(msgs) > 0 {
		out.NextCursor = msgs[len(msgs)-1].ID
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
	Drafts   map[string]Draft
	SMTP     SMTPSubmitter
	Signer   OpenPGPSigner
	Resolver SenderIdentityResolver
	Audit    audit.Writer
}

func (s *Sender) SaveDraft(d Draft) Draft {
	if s.Drafts == nil {
		s.Drafts = map[string]Draft{}
	}
	if d.ID == "" {
		for {
			d.ID = "draft-" + strings.ReplaceAll(safeToken(12), "=", "")
			if _, exists := s.Drafts[d.ID]; !exists {
				break
			}
		}
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
	if s.Resolver == nil {
		return Draft{}, errors.New("exact sender resolver required")
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
	identity, err := s.Resolver.ResolveSender(ctx, d.SigningFingerprint, d.From, "")
	if err != nil || identity.Address != d.From || identity.Fingerprint != d.SigningFingerprint {
		s.audit(ctx, d, "failure", "exact sender identity binding failed", SignatureStatus{})
		d.State = "failed"
		s.Drafts[id] = d
		if err != nil {
			return d, err
		}
		return d, errors.New("exact sender identity binding failed")
	}
	mime, err := BuildMIME(d)
	if err != nil {
		d.State = "failed"
		s.Drafts[id] = d
		return d, err
	}
	signed, status, err := s.Signer.SignMIME(ctx, identity, mime)
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
	if err := validHeaderValue(d.Subject); err != nil {
		return nil, err
	}
	from, err := mail.ParseAddress(d.From)
	if err != nil {
		return nil, errors.New("invalid from")
	}
	to, err := mail.ParseAddress(d.To)
	if err != nil {
		return nil, errors.New("invalid recipient")
	}
	var body strings.Builder
	mw := multipart.NewWriter(&body)
	part, err := mw.CreatePart(textproto.MIMEHeader{"Content-Type": {"text/plain; charset=utf-8"}})
	if err != nil {
		return nil, err
	}
	_, _ = part.Write([]byte(d.Body))
	for _, a := range d.Attachments {
		a = SafeAttachment(a)
		ct := safeContentType(a.ContentType)
		part, err = mw.CreatePart(textproto.MIMEHeader{"Content-Disposition": {mime.FormatMediaType("attachment", map[string]string{"filename": a.Filename})}, "Content-Type": {ct}})
		if err != nil {
			return nil, err
		}
		_, _ = part.Write(a.Content)
	}
	if err := mw.Close(); err != nil {
		return nil, err
	}
	var b strings.Builder
	b.WriteString("From: " + from.String() + "\r\n")
	b.WriteString("To: " + to.String() + "\r\n")
	b.WriteString("Date: " + time.Now().UTC().Format(time.RFC1123Z) + "\r\n")
	b.WriteString("Subject: " + d.Subject + "\r\n")
	b.WriteString("MIME-Version: 1.0\r\n")
	b.WriteString("Content-Type: multipart/mixed; boundary=\"" + mw.Boundary() + "\"\r\n\r\n")
	b.WriteString(body.String())
	return []byte(b.String()), nil
}

func SanitizeHTML(in string) string {
	// Until a parser allowlist is carried, hostile email HTML is rendered as text.
	// This is intentionally boring and safe; regex sanitizers are not a security boundary.
	clean := stripDangerousControls(in)
	for _, tag := range []string{"script", "style", "iframe", "object", "embed", "svg", "math"} {
		re := regexp.MustCompile(`(?is)<` + tag + `[^>]*>.*?</` + tag + `>`)
		clean = re.ReplaceAllString(clean, "")
	}
	re := regexp.MustCompile(`(?i)\s+on[a-z]+\s*=\s*("[^"]*"|'[^']*'|[^\s>]+)`)
	clean = re.ReplaceAllString(clean, "")
	re = regexp.MustCompile(`(?i)javascript\s*:`)
	clean = re.ReplaceAllString(clean, "blocked:")
	re = regexp.MustCompile(`(?i)https?://[^\s"'<>]+`)
	clean = re.ReplaceAllString(clean, "remote-image-blocked")
	return html.EscapeString(clean)
}
func CSP() string {
	return "default-src 'none'; img-src 'self' data:; style-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
}
func safeToken(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return strings.ReplaceAll(time.Now().UTC().Format("20060102150405.000000000"), ".", "")
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func validHeaderValue(v string) error {
	if strings.ContainsAny(v, "\r\n") {
		return errors.New("header injection rejected")
	}
	return nil
}

func safeContentType(v string) string {
	v = strings.TrimSpace(v)
	if v == "" || strings.ContainsAny(v, "\r\n;") {
		return "application/octet-stream"
	}
	mt, _, err := mime.ParseMediaType(v)
	if err != nil || mt == "" {
		return "application/octet-stream"
	}
	return mt
}

func stripDangerousControls(v string) string {
	re := regexp.MustCompile(`[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]`)
	return re.ReplaceAllString(v, "")
}

func SafeAttachment(a Attachment) Attachment {
	re := regexp.MustCompile(`[\x00-\x1f\x7f"\r\n]`)
	a.Filename = re.ReplaceAllString(a.Filename, "_")
	a.Filename = strings.ReplaceAll(a.Filename, "/", "_")
	a.Filename = strings.ReplaceAll(a.Filename, "..", "_")
	a.ContentType = safeContentType(a.ContentType)
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
