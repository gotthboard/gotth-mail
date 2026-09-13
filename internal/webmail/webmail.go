package webmail

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"html"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net/mail"
	"net/textproto"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"forgejo/gotthboard/gotth-mail/internal/audit"
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
type ExactSenderVerifier interface {
	VerifyExactSender(context.Context, []byte, Identity) (SignatureStatus, error)
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
	MessageID                   string
	Date                        time.Time
}
type DraftStore interface {
	PutDraft(context.Context, Draft) error
	Draft(context.Context, string) (Draft, bool, error)
}

type Sender struct {
	Drafts   map[string]Draft
	Store    DraftStore
	SMTP     SMTPSubmitter
	Signer   OpenPGPSigner
	Resolver SenderIdentityResolver
	Audit    audit.Writer
}

type memoryDraftStore struct{ drafts *map[string]Draft }

func (m memoryDraftStore) PutDraft(ctx context.Context, d Draft) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if *m.drafts == nil {
		*m.drafts = map[string]Draft{}
	}
	(*m.drafts)[d.ID] = d
	return nil
}
func (m memoryDraftStore) Draft(ctx context.Context, id string) (Draft, bool, error) {
	if err := ctx.Err(); err != nil {
		return Draft{}, false, err
	}
	if *m.drafts == nil {
		return Draft{}, false, nil
	}
	d, ok := (*m.drafts)[id]
	return d, ok, nil
}

type SQLDraftStore struct{ DB *sql.DB }

func (s SQLDraftStore) PutDraft(ctx context.Context, d Draft) error {
	if s.DB == nil {
		return errors.New("webmail draft db required")
	}
	if d.ID == "" || d.From == "" {
		return errors.New("draft id and mailbox required")
	}
	state := d.State
	if state == "" {
		state = "draft"
	}
	attachments, err := json.Marshal(d.Attachments)
	if err != nil {
		return err
	}
	res, err := s.DB.ExecContext(ctx, `INSERT INTO webmail_drafts(id, mailbox, to_addr, subject, body_text, signing_fingerprint, state, reply_to, forward_of, attachments_json, created_at, updated_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP) ON CONFLICT (id) DO UPDATE SET to_addr=EXCLUDED.to_addr, subject=EXCLUDED.subject, body_text=EXCLUDED.body_text, signing_fingerprint=EXCLUDED.signing_fingerprint, state=EXCLUDED.state, reply_to=EXCLUDED.reply_to, forward_of=EXCLUDED.forward_of, attachments_json=EXCLUDED.attachments_json, updated_at=CURRENT_TIMESTAMP WHERE webmail_drafts.mailbox=EXCLUDED.mailbox`, d.ID, strings.ToLower(d.From), d.To, d.Subject, d.Body, d.SigningFingerprint, state, d.ReplyTo, d.ForwardOf, string(attachments))
	if err != nil {
		return err
	}
	if n, err := res.RowsAffected(); err == nil && n == 0 {
		return errors.New("draft mailbox ownership mismatch")
	}
	return nil
}
func (s SQLDraftStore) Draft(ctx context.Context, id string) (Draft, bool, error) {
	if s.DB == nil {
		return Draft{}, false, errors.New("webmail draft db required")
	}
	var d Draft
	var attachments string
	err := s.DB.QueryRowContext(ctx, `SELECT id, mailbox, to_addr, subject, body_text, signing_fingerprint, state, reply_to, forward_of, attachments_json FROM webmail_drafts WHERE id=$1`, id).Scan(&d.ID, &d.From, &d.To, &d.Subject, &d.Body, &d.SigningFingerprint, &d.State, &d.ReplyTo, &d.ForwardOf, &attachments)
	if errors.Is(err, sql.ErrNoRows) {
		return Draft{}, false, nil
	}
	if err != nil {
		return Draft{}, false, err
	}
	if attachments != "" {
		if err := json.Unmarshal([]byte(attachments), &d.Attachments); err != nil {
			return Draft{}, false, err
		}
	}
	return d, true, nil
}

func (s *Sender) draftStore() DraftStore {
	if s.Store != nil {
		return s.Store
	}
	return memoryDraftStore{drafts: &s.Drafts}
}

func (s *Sender) putDraft(ctx context.Context, d Draft) error { return s.draftStore().PutDraft(ctx, d) }

func (s *Sender) SaveDraft(d Draft) Draft {
	saved, err := s.SaveDraftContext(context.Background(), d)
	if err != nil {
		d.State = "failed"
		return d
	}
	return saved
}

func (s *Sender) SaveDraftContext(ctx context.Context, d Draft) (Draft, error) {
	store := s.draftStore()
	if d.ID == "" {
		for {
			d.ID = "draft-" + strings.ReplaceAll(safeToken(12), "=", "")
			if _, exists, err := store.Draft(ctx, d.ID); err != nil {
				return Draft{}, err
			} else if !exists {
				break
			}
		}
	}
	d.State = "draft"
	if err := store.PutDraft(ctx, d); err != nil {
		return Draft{}, err
	}
	return d, nil
}
func (s *Sender) Reply(orig Message, from, body string) Draft {
	return s.SaveDraft(Draft{From: from, To: orig.From, Subject: "Re: " + orig.Subject, Body: body, ReplyTo: orig.ID})
}
func (s *Sender) Forward(orig Message, from, to string) Draft {
	return s.SaveDraft(Draft{From: from, To: to, Subject: "Fwd: " + orig.Subject, Body: orig.BodyText, ForwardOf: orig.ID, Attachments: orig.Attachments})
}
func (s *Sender) Draft(id string) (Draft, bool) {
	d, ok, err := s.DraftContext(context.Background(), id)
	if err != nil {
		return Draft{}, false
	}
	return d, ok
}

func (s *Sender) DraftContext(ctx context.Context, id string) (Draft, bool, error) {
	return s.draftStore().Draft(ctx, id)
}

func (s *Sender) Submit(ctx context.Context, id string) (Draft, error) {
	d, ok, err := s.DraftContext(ctx, id)
	if err != nil {
		return Draft{}, err
	}
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
		_ = s.putDraft(ctx, d)
		return d, errors.New("OpenPGP signing identity required")
	}
	d.State = "queued_for_submission"
	if err := s.putDraft(ctx, d); err != nil {
		return d, err
	}
	identity, err := s.Resolver.ResolveSender(ctx, d.SigningFingerprint, d.From, "")
	if err != nil || identity.Address != d.From || identity.Fingerprint != d.SigningFingerprint {
		s.audit(ctx, d, "failure", "exact sender identity binding failed", SignatureStatus{})
		d.State = "failed"
		_ = s.putDraft(ctx, d)
		if err != nil {
			return d, err
		}
		return d, errors.New("exact sender identity binding failed")
	}
	mime, err := BuildMIME(d)
	if err != nil {
		d.State = "failed"
		_ = s.putDraft(ctx, d)
		return d, err
	}
	signed, status, err := s.Signer.SignMIME(ctx, identity, mime)
	if err != nil || !status.Signed || status.Identity != d.From || status.Fingerprint != d.SigningFingerprint {
		s.audit(ctx, d, "failure", "openpgp signing identity invalid", status)
		d.State = "failed"
		_ = s.putDraft(ctx, d)
		if err != nil {
			return d, err
		}
		return d, errors.New("OpenPGP signing identity invalid")
	}
	d.State = "submitted"
	if err := s.putDraft(ctx, d); err != nil {
		return d, err
	}
	if err := ValidateOpenPGPMIME(signed); err != nil {
		s.audit(ctx, d, "failure", err.Error(), status)
		d.State = "failed"
		_ = s.putDraft(ctx, d)
		return d, err
	}
	if err := s.SMTP.Submit(ctx, Envelope{From: d.From, To: []string{d.To}}, signed); err != nil {
		s.audit(ctx, d, "failure", err.Error(), status)
		d.State = "failed"
		_ = s.putDraft(ctx, d)
		return d, err
	}
	d.State = "sent"
	if err := s.putDraft(ctx, d); err != nil {
		return d, err
	}
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
	if err := validMIMEText(d.Body); err != nil {
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
	if !asciiAddress(from.Address) || !asciiAddress(to.Address) {
		return nil, errors.New("SMTPUTF8 addresses are not supported")
	}
	messageID, err := messageID(d.MessageID, from.Address)
	if err != nil {
		return nil, err
	}
	date := d.Date.UTC()
	if d.Date.IsZero() {
		date = time.Now().UTC()
	}
	var body strings.Builder
	mw := multipart.NewWriter(&body)
	part, err := mw.CreatePart(textproto.MIMEHeader{
		"Content-Type":              {"text/plain; charset=utf-8"},
		"Content-Transfer-Encoding": {"quoted-printable"},
	})
	if err != nil {
		return nil, err
	}
	qp := quotedprintable.NewWriter(part)
	if _, err := qp.Write([]byte(d.Body)); err != nil {
		return nil, err
	}
	if err := qp.Close(); err != nil {
		return nil, err
	}
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
	b.WriteString("Date: " + date.Format(time.RFC1123Z) + "\r\n")
	b.WriteString("Message-ID: " + messageID + "\r\n")
	b.WriteString("Subject: " + mime.QEncoding.Encode("utf-8", d.Subject) + "\r\n")
	b.WriteString("MIME-Version: 1.0\r\n")
	b.WriteString("Content-Type: multipart/mixed; boundary=\"" + mw.Boundary() + "\"\r\n\r\n")
	b.WriteString(body.String())
	return []byte(b.String()), nil
}

func messageID(v, from string) (string, error) {
	v = strings.TrimSpace(v)
	if v == "" {
		domain := "localhost"
		if _, d, ok := strings.Cut(from, "@"); ok && d != "" {
			domain = strings.ToLower(d)
		}
		v = "<gotth-mail-" + safeToken(18) + "@" + domain + ">"
	}
	if strings.ContainsAny(v, "\r\n") || len(v) > 255 || !strings.HasPrefix(v, "<") || !strings.HasSuffix(v, ">") {
		return "", errors.New("invalid message id")
	}
	inner := strings.TrimSuffix(strings.TrimPrefix(v, "<"), ">")
	if strings.Count(inner, "@") != 1 || strings.ContainsAny(inner, " <>\t") {
		return "", errors.New("invalid message id")
	}
	return v, nil
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
	if !utf8.ValidString(v) || strings.ContainsAny(v, "\r\n") {
		return errors.New("header injection rejected")
	}
	for _, r := range v {
		if r < 0x20 || r == 0x7f {
			return errors.New("header control character rejected")
		}
	}
	return nil
}

func validMIMEText(v string) error {
	if !utf8.ValidString(v) {
		return errors.New("message body must be valid UTF-8")
	}
	for _, r := range v {
		if (r < 0x20 && r != '\r' && r != '\n' && r != '\t') || r == 0x7f {
			return errors.New("message body control character rejected")
		}
	}
	return nil
}

func asciiAddress(v string) bool {
	if v == "" {
		return false
	}
	for i := 0; i < len(v); i++ {
		if v[i] > 0x7f {
			return false
		}
	}
	return true
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
	_, _, err := splitOpenPGPMIME(b)
	if err != nil {
		return errors.New("invalid OpenPGP/MIME structure")
	}
	return nil
}
