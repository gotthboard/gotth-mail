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
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"forgejo/gotthboard/gotth-mail/internal/audit"
	"forgejo/gotthboard/gotth-mail/internal/outboundpolicy"
)

type Message struct {
	ID, Folder, From, To, Cc, Subject, BodyHTML, BodyText string
	Date                                                  time.Time
	Flags                                                 []string
	Attachments                                           []Attachment
	HasAttachments                                        bool
}
type Attachment struct {
	Filename, ContentType string
	Size                  int64
	Content               []byte
}
type MessageSummary struct {
	ID, From, Subject, Date string
	Flags                   []string
	HasAttachments          bool
}
type FolderInfo struct {
	Name   string
	Unread int
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
	Quota(context.Context, string) (int64, int64, error)
}
type IMAPMutator interface {
	SetFlag(context.Context, string, string, string, string, bool) error
	Move(context.Context, string, string, string, string) error
	Delete(context.Context, string, string, string) error
}
type IMAPFolderLister interface {
	ListFoldersDetailed(context.Context, string) ([]FolderInfo, error)
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
type MailboxIdentityResolver interface {
	DefaultIdentity(context.Context, string) (Identity, error)
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
func (c Client) FolderListDetailed(ctx context.Context, user string) ([]FolderInfo, error) {
	if c.IMAP == nil {
		return nil, errors.New("imap client required")
	}
	if detailed, ok := c.IMAP.(IMAPFolderLister); ok {
		folders, err := detailed.ListFoldersDetailed(ctx, user)
		sort.Slice(folders, func(i, j int) bool { return folders[i].Name < folders[j].Name })
		return folders, err
	}
	folders, err := c.FolderList(ctx, user)
	if err != nil {
		return nil, err
	}
	out := make([]FolderInfo, 0, len(folders))
	for _, folder := range folders {
		out = append(out, FolderInfo{Name: folder})
	}
	return out, nil
}
func (c Client) Quota(ctx context.Context, user string) (int64, int64, error) {
	if c.IMAP == nil {
		return 0, 0, errors.New("imap client required")
	}
	return c.IMAP.Quota(ctx, user)
}
func (c Client) List(ctx context.Context, user, folder, cursor string, limit int) (ListResult, error) {
	if c.IMAP == nil {
		return ListResult{}, errors.New("imap client required")
	}
	if limit <= 0 || limit > 100 {
		limit = 50
	}
	msgs, err := c.IMAP.ListMessages(ctx, user, folder, cursor, limit+1)
	if err != nil {
		return ListResult{}, err
	}
	hadMore := len(msgs) > limit
	if hadMore {
		msgs = msgs[:limit]
	}
	out := ListResult{Folder: folder, Cursor: cursor}
	for _, m := range msgs {
		out.Messages = append(out.Messages, MessageSummary{ID: m.ID, From: m.From, Subject: m.Subject, Date: m.Date.Format(time.RFC3339), Flags: append([]string(nil), m.Flags...), HasAttachments: m.HasAttachments || len(m.Attachments) > 0})
	}
	if hadMore && len(msgs) > 0 {
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
	if len(query) > 200 || strings.ContainsAny(query, "\r\n\x00") {
		return ListResult{}, errors.New("invalid search query")
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
		out.Messages = append(out.Messages, MessageSummary{ID: m.ID, From: m.From, Subject: m.Subject, Date: m.Date.Format(time.RFC3339), Flags: append([]string(nil), m.Flags...), HasAttachments: m.HasAttachments || len(m.Attachments) > 0})
	}
	if hadMore && len(msgs) > 0 {
		out.NextCursor = msgs[len(msgs)-1].ID
	}
	return out, nil
}

func (c Client) SetFlag(ctx context.Context, user, folder, id, flag string, enabled bool) error {
	mutator, ok := c.IMAP.(IMAPMutator)
	if !ok {
		return errors.New("imap mutation unavailable")
	}
	return mutator.SetFlag(ctx, user, folder, id, flag, enabled)
}

func (c Client) Move(ctx context.Context, user, folder, id, destination string) error {
	mutator, ok := c.IMAP.(IMAPMutator)
	if !ok {
		return errors.New("imap mutation unavailable")
	}
	return mutator.Move(ctx, user, folder, id, destination)
}

func (c Client) Delete(ctx context.Context, user, folder, id string) error {
	mutator, ok := c.IMAP.(IMAPMutator)
	if !ok {
		return errors.New("imap mutation unavailable")
	}
	return mutator.Delete(ctx, user, folder, id)
}

type Draft struct {
	ID, From, To, Subject, Body string
	Cc, Bcc                     []string
	Attachments                 []Attachment
	State                       string
	ReplyTo, ForwardOf          string
	SigningFingerprint          string
	MessageID                   string
	Date                        time.Time
}
type DraftSummary struct {
	ID, To, Subject, State string
}
type DraftStore interface {
	PutDraft(context.Context, Draft) error
	Draft(context.Context, string) (Draft, bool, error)
}
type DraftLister interface {
	ListDrafts(context.Context, string, int) ([]DraftSummary, error)
}
type DraftUpdater interface {
	UpdateDraft(context.Context, Draft) (Draft, bool, error)
}

type DraftSubmitClaimer interface {
	ClaimDraftForSubmission(context.Context, string) (Draft, bool, error)
}

type Sender struct {
	mu       sync.Mutex
	Drafts   map[string]Draft
	Store    DraftStore
	SMTP     SMTPSubmitter
	Signer   OpenPGPSigner
	Verifier ExactSenderVerifier
	Resolver SenderIdentityResolver
	Audit    audit.Writer
	Policy   OutboundPolicyEvaluator
}

func (s *Sender) DefaultIdentity(ctx context.Context, mailbox string) (Identity, error) {
	resolver, ok := s.Resolver.(MailboxIdentityResolver)
	if !ok {
		return Identity{}, errors.New("webmail mailbox identity unavailable")
	}
	return resolver.DefaultIdentity(ctx, mailbox)
}

type OutboundPolicyEvaluator interface {
	Decide(context.Context, string, outboundpolicy.EnforcementRequest) (outboundpolicy.Decision, error)
}

type ExpandedOutboundPolicyEvaluator interface {
	DecideSMTPRecipient(context.Context, string, string, string, string) (outboundpolicy.Decision, error)
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
func (m memoryDraftStore) ListDrafts(ctx context.Context, mailbox string, limit int) ([]DraftSummary, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if limit <= 0 || limit > 100 {
		limit = 100
	}
	out := make([]DraftSummary, 0, limit)
	for _, draft := range *m.drafts {
		if strings.EqualFold(draft.From, mailbox) && (draft.State == "" || draft.State == "draft" || draft.State == "failed") {
			out = append(out, DraftSummary{ID: draft.ID, To: draft.To, Subject: draft.Subject, State: draft.State})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID > out[j].ID })
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}
func (m memoryDraftStore) UpdateDraft(ctx context.Context, d Draft) (Draft, bool, error) {
	if err := ctx.Err(); err != nil {
		return Draft{}, false, err
	}
	current, ok := (*m.drafts)[d.ID]
	if !ok || !strings.EqualFold(current.From, d.From) || (current.State != "" && current.State != "draft" && current.State != "failed") {
		return Draft{}, false, nil
	}
	d.State = "draft"
	(*m.drafts)[d.ID] = d
	return d, true, nil
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
	cc, err := json.Marshal(d.Cc)
	if err != nil {
		return err
	}
	bcc, err := json.Marshal(d.Bcc)
	if err != nil {
		return err
	}
	res, err := s.DB.ExecContext(ctx, `INSERT INTO webmail_drafts(id, mailbox, to_addr, subject, body_text, signing_fingerprint, state, reply_to, forward_of, attachments_json, cc_json, bcc_json, created_at, updated_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP) ON CONFLICT (id) DO UPDATE SET to_addr=EXCLUDED.to_addr, subject=EXCLUDED.subject, body_text=EXCLUDED.body_text, signing_fingerprint=EXCLUDED.signing_fingerprint, state=EXCLUDED.state, reply_to=EXCLUDED.reply_to, forward_of=EXCLUDED.forward_of, attachments_json=EXCLUDED.attachments_json, cc_json=EXCLUDED.cc_json, bcc_json=EXCLUDED.bcc_json, updated_at=CURRENT_TIMESTAMP WHERE webmail_drafts.mailbox=EXCLUDED.mailbox`, d.ID, strings.ToLower(d.From), d.To, d.Subject, d.Body, d.SigningFingerprint, state, d.ReplyTo, d.ForwardOf, string(attachments), string(cc), string(bcc))
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
	d, err := scanSQLDraft(s.DB.QueryRowContext(ctx, `SELECT id, mailbox, to_addr, subject, body_text, signing_fingerprint, state, reply_to, forward_of, attachments_json, cc_json, bcc_json FROM webmail_drafts WHERE id=$1`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return Draft{}, false, nil
	}
	if err != nil {
		return Draft{}, false, err
	}
	return d, true, nil
}

func (s SQLDraftStore) ClaimDraftForSubmission(ctx context.Context, id string) (Draft, bool, error) {
	if s.DB == nil {
		return Draft{}, false, errors.New("webmail draft db required")
	}
	d, err := scanSQLDraft(s.DB.QueryRowContext(ctx, `UPDATE webmail_drafts SET state='queued_for_submission',updated_at=CURRENT_TIMESTAMP WHERE id=$1 AND state IN ('draft','failed') RETURNING id,mailbox,to_addr,subject,body_text,signing_fingerprint,state,reply_to,forward_of,attachments_json,cc_json,bcc_json`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return Draft{}, false, nil
	}
	if err != nil {
		return Draft{}, false, err
	}
	return d, true, nil
}

func (s SQLDraftStore) ListDrafts(ctx context.Context, mailbox string, limit int) ([]DraftSummary, error) {
	if s.DB == nil {
		return nil, errors.New("webmail draft db required")
	}
	if limit <= 0 || limit > 100 {
		limit = 100
	}
	rows, err := s.DB.QueryContext(ctx, `SELECT id,to_addr,subject,state FROM webmail_drafts WHERE mailbox=$1 AND state IN ('draft','failed') ORDER BY updated_at DESC,id DESC LIMIT $2`, strings.ToLower(mailbox), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]DraftSummary, 0, limit)
	for rows.Next() {
		var draft DraftSummary
		if err := rows.Scan(&draft.ID, &draft.To, &draft.Subject, &draft.State); err != nil {
			return nil, err
		}
		out = append(out, draft)
	}
	return out, rows.Err()
}

func (s SQLDraftStore) UpdateDraft(ctx context.Context, d Draft) (Draft, bool, error) {
	if s.DB == nil {
		return Draft{}, false, errors.New("webmail draft db required")
	}
	attachments, err := json.Marshal(d.Attachments)
	if err != nil {
		return Draft{}, false, err
	}
	cc, err := json.Marshal(d.Cc)
	if err != nil {
		return Draft{}, false, err
	}
	bcc, err := json.Marshal(d.Bcc)
	if err != nil {
		return Draft{}, false, err
	}
	updated, err := scanSQLDraft(s.DB.QueryRowContext(ctx, `UPDATE webmail_drafts SET to_addr=$3,subject=$4,body_text=$5,signing_fingerprint=$6,state='draft',reply_to=$7,forward_of=$8,attachments_json=$9,cc_json=$10,bcc_json=$11,updated_at=CURRENT_TIMESTAMP WHERE id=$1 AND mailbox=$2 AND state IN ('draft','failed') RETURNING id,mailbox,to_addr,subject,body_text,signing_fingerprint,state,reply_to,forward_of,attachments_json,cc_json,bcc_json`, d.ID, strings.ToLower(d.From), d.To, d.Subject, d.Body, d.SigningFingerprint, d.ReplyTo, d.ForwardOf, string(attachments), string(cc), string(bcc)))
	if errors.Is(err, sql.ErrNoRows) {
		return Draft{}, false, nil
	}
	if err != nil {
		return Draft{}, false, err
	}
	return updated, true, nil
}

type sqlDraftScanner interface{ Scan(...any) error }

func scanSQLDraft(row sqlDraftScanner) (Draft, error) {
	var d Draft
	var attachments, cc, bcc string
	if err := row.Scan(&d.ID, &d.From, &d.To, &d.Subject, &d.Body, &d.SigningFingerprint, &d.State, &d.ReplyTo, &d.ForwardOf, &attachments, &cc, &bcc); err != nil {
		return Draft{}, err
	}
	if attachments != "" {
		if err := json.Unmarshal([]byte(attachments), &d.Attachments); err != nil {
			return Draft{}, err
		}
	}
	if err := json.Unmarshal([]byte(cc), &d.Cc); err != nil {
		return Draft{}, err
	}
	if err := json.Unmarshal([]byte(bcc), &d.Bcc); err != nil {
		return Draft{}, err
	}
	return d, nil
}

func (s *Sender) draftStore() DraftStore {
	if s.Store != nil {
		return s.Store
	}
	return memoryDraftStore{drafts: &s.Drafts}
}

func (s *Sender) putDraft(ctx context.Context, d Draft) error {
	if s.Store == nil {
		s.mu.Lock()
		defer s.mu.Unlock()
	}
	return s.draftStore().PutDraft(ctx, d)
}

func (s *Sender) SaveDraft(d Draft) Draft {
	saved, err := s.SaveDraftContext(context.Background(), d)
	if err != nil {
		d.State = "failed"
		return d
	}
	return saved
}

func (s *Sender) SaveDraftContext(ctx context.Context, d Draft) (Draft, error) {
	if s.Store == nil {
		s.mu.Lock()
		defer s.mu.Unlock()
	}
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
		d.State = "draft"
		if err := store.PutDraft(ctx, d); err != nil {
			return Draft{}, err
		}
		return d, nil
	}
	updater, ok := store.(DraftUpdater)
	if !ok {
		return Draft{}, errors.New("webmail draft update unavailable")
	}
	updated, ok, err := updater.UpdateDraft(ctx, d)
	if err != nil {
		return Draft{}, err
	}
	if !ok {
		return Draft{}, errors.New("draft is no longer editable")
	}
	return updated, nil
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
	if s.Store == nil {
		s.mu.Lock()
		defer s.mu.Unlock()
	}
	return s.draftStore().Draft(ctx, id)
}

func (s *Sender) ListDrafts(ctx context.Context, mailbox string, limit int) ([]DraftSummary, error) {
	if s.Store == nil {
		s.mu.Lock()
		defer s.mu.Unlock()
	}
	lister, ok := s.draftStore().(DraftLister)
	if !ok {
		return nil, errors.New("webmail draft listing unavailable")
	}
	return lister.ListDrafts(ctx, mailbox, limit)
}

func (s *Sender) UpdateDraft(ctx context.Context, draft Draft) (Draft, bool, error) {
	if s.Store == nil {
		s.mu.Lock()
		defer s.mu.Unlock()
	}
	updater, ok := s.draftStore().(DraftUpdater)
	if !ok {
		return Draft{}, false, errors.New("webmail draft update unavailable")
	}
	return updater.UpdateDraft(ctx, draft)
}

func (s *Sender) claimDraftForSubmission(ctx context.Context, id string) (Draft, bool, error) {
	store := s.draftStore()
	if claimer, ok := store.(DraftSubmitClaimer); ok {
		return claimer.ClaimDraftForSubmission(ctx, id)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	d, ok, err := store.Draft(ctx, id)
	if err != nil || !ok {
		return d, ok, err
	}
	if d.State != "" && d.State != "draft" && d.State != "failed" {
		return Draft{}, false, nil
	}
	d.State = "queued_for_submission"
	if err := store.PutDraft(ctx, d); err != nil {
		return Draft{}, false, err
	}
	return d, true, nil
}

// Submit applies atomic outbound policy before signing or SMTP, then preserves
// the existing exact-sender and delivery-acceptance boundaries.
// Complexity: time O(r*(p+n)+m+a), Omega(r+m); auxiliary space O(r*n+m+a),
// where r is bounded recipients, p policy latency, n address bytes, m MIME
// bytes, and a attachment bytes; signing, store, audit, and SMTP are additive.
func (s *Sender) Submit(ctx context.Context, id string) (Draft, error) {
	if s.SMTP == nil {
		return Draft{}, errors.New("smtp submitter required")
	}
	if s.Signer == nil {
		return Draft{}, errors.New("openpgp signer required")
	}
	if s.Resolver == nil {
		return Draft{}, errors.New("exact sender resolver required")
	}
	verifier := s.Verifier
	if verifier == nil {
		verifier, _ = s.Signer.(ExactSenderVerifier)
	}
	if verifier == nil {
		return Draft{}, errors.New("exact sender verifier required")
	}
	if s.Policy == nil {
		return Draft{}, errors.New("outbound policy evaluator required")
	}
	d, ok, err := s.claimDraftForSubmission(ctx, id)
	if err != nil {
		return Draft{}, err
	}
	if !ok {
		return Draft{}, errors.New("draft not found or no longer submittable")
	}
	recipients, err := draftRecipients(d)
	if err != nil {
		d.State = "failed"
		_ = s.putDraft(ctx, d)
		return Draft{}, errors.New("invalid recipient")
	}
	for i, recipient := range recipients {
		correlationID := "webmail-policy:" + d.ID + ":" + safeRecipientOrdinal(i)
		var policyDecision outboundpolicy.Decision
		var policyErr error
		if expanded, ok := s.Policy.(ExpandedOutboundPolicyEvaluator); ok {
			policyDecision, policyErr = expanded.DecideSMTPRecipient(ctx, correlationID, d.From, d.From, recipient)
		} else {
			policyDecision, policyErr = s.Policy.Decide(ctx, correlationID, outboundpolicy.EnforcementRequest{
				Stage:                outboundpolicy.StageSubmission,
				AuthenticatedMailbox: d.From,
				EnvelopeSender:       d.From,
				Recipient:            recipient,
			})
		}
		if policyErr != nil || policyDecision.Action != outboundpolicy.ActionOK {
			s.audit(ctx, d, "failure", "outbound_policy_"+string(policyDecision.Reason), SignatureStatus{})
			d.State = "failed"
			_ = s.putDraft(ctx, d)
			return d, errors.New("outbound policy rejected submission")
		}
	}
	if d.SigningFingerprint == "" {
		s.audit(ctx, d, "failure", "openpgp signing identity required", SignatureStatus{})
		d.State = "failed"
		_ = s.putDraft(ctx, d)
		return d, errors.New("OpenPGP signing identity required")
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
	verified, err := verifier.VerifyExactSender(ctx, signed, identity)
	if err != nil || !verified.Signed || verified.Identity != d.From || verified.Fingerprint != d.SigningFingerprint {
		s.audit(ctx, d, "failure", "openpgp exact sender verification failed", verified)
		d.State = "failed"
		_ = s.putDraft(ctx, d)
		if err != nil {
			return d, err
		}
		return d, errors.New("OpenPGP exact sender verification failed")
	}
	if err := s.SMTP.Submit(ctx, Envelope{From: d.From, To: recipients}, signed); err != nil {
		s.audit(ctx, d, "failure", err.Error(), status)
		d.State = "failed"
		var deliveryErr *SMTPDeliveryError
		if errors.As(err, &deliveryErr) && deliveryErr.Class == SMTPFailureAmbiguous {
			d.State = "delivery_uncertain"
		}
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
	if _, err := draftRecipients(d); err != nil {
		return nil, errors.New("invalid recipient")
	}
	from, err := mail.ParseAddress(d.From)
	if err != nil {
		return nil, errors.New("invalid from")
	}
	to, err := exactEnvelopeAddress(d.To)
	if err != nil {
		return nil, errors.New("invalid recipient")
	}
	cc := make([]string, len(d.Cc))
	for i, raw := range d.Cc {
		cc[i], err = exactEnvelopeAddress(raw)
		if err != nil {
			return nil, errors.New("invalid cc recipient")
		}
	}
	if !asciiAddress(from.Address) || !asciiAddress(to) {
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
	b.WriteString("To: " + to + "\r\n")
	if len(cc) > 0 {
		b.WriteString("Cc: " + strings.Join(cc, ", ") + "\r\n")
	}
	b.WriteString("Date: " + date.Format(time.RFC1123Z) + "\r\n")
	b.WriteString("Message-ID: " + messageID + "\r\n")
	b.WriteString("Subject: " + mime.QEncoding.Encode("utf-8", d.Subject) + "\r\n")
	b.WriteString("MIME-Version: 1.0\r\n")
	b.WriteString("Content-Type: multipart/mixed; boundary=\"" + mw.Boundary() + "\"\r\n\r\n")
	b.WriteString(body.String())
	return []byte(b.String()), nil
}

// draftRecipients returns a deduplicated ordered envelope set covering To,
// CC, and BCC while keeping BCC out of MIME headers.
// Complexity: time O(r*n), Omega(r); auxiliary space O(r*n), where r is capped
// at 1000 and n is bounded address length.
func draftRecipients(d Draft) ([]string, error) {
	if len(d.Cc)+len(d.Bcc)+1 > 1000 {
		return nil, errors.New("recipient limit exceeded")
	}
	raw := make([]string, 0, 1+len(d.Cc)+len(d.Bcc))
	raw = append(raw, d.To)
	raw = append(raw, d.Cc...)
	raw = append(raw, d.Bcc...)
	seen := make(map[string]bool, len(raw))
	recipients := make([]string, 0, len(raw))
	for _, value := range raw {
		address, err := exactEnvelopeAddress(value)
		if err != nil || !asciiAddress(address) {
			return nil, errors.New("invalid envelope recipient")
		}
		key := strings.ToLower(address)
		if !seen[key] {
			seen[key] = true
			recipients = append(recipients, address)
		}
	}
	return recipients, nil
}

// exactEnvelopeAddress rejects display names and trimming ambiguity.
// Complexity: time and auxiliary space O(n), Omega(1), where n is bounded.
func exactEnvelopeAddress(value string) (string, error) {
	if value == "" || strings.TrimSpace(value) != value || len(value) > 254 {
		return "", errors.New("invalid envelope address")
	}
	parsed, err := mail.ParseAddress(value)
	if err != nil || parsed.Name != "" || parsed.Address != value || !asciiAddress(parsed.Address) {
		return "", errors.New("invalid envelope address")
	}
	return parsed.Address, nil
}

// safeRecipientOrdinal produces a bounded non-address correlation suffix.
// Complexity: time and auxiliary space O(1).
func safeRecipientOrdinal(index int) string {
	return strconv.Itoa(index)
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
