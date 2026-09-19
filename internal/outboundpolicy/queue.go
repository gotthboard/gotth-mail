package outboundpolicy

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/lib/pq"
)

type SourceKind string

const (
	SourceAuthenticatedMailbox SourceKind = "authenticated_mailbox"
	SourceEnvelopeSender       SourceKind = "envelope_sender"
	SourceSystemSender         SourceKind = "system_sender"
	SourceAlias                SourceKind = "alias"
	SourceForward              SourceKind = "forward"
	SourceList                 SourceKind = "list"
	SourceCatchAll             SourceKind = "catch_all"
)

type HoldState string

const (
	HoldPending             HoldState = "pending"
	HoldRequired            HoldState = "hold_required"
	HoldReconciling         HoldState = "reconciling"
	HoldApplied             HoldState = "held"
	HoldReconciliationError HoldState = "reconciliation_error"
	HoldReleased            HoldState = "released"
)

const (
	maxQueueRecipients = 10_000
	maxQueueSources    = 64
	maxQueueObjectID   = 320
)

type QueueSource struct {
	Kind     SourceKind `json:"kind"`
	ObjectID string     `json:"object_id"`
}

type QueueRegistration struct {
	QueueID            string        `json:"queue_id"`
	ArrivalFingerprint string        `json:"arrival_fingerprint"`
	EnvelopeSender     string        `json:"envelope_sender"`
	Recipients         []string      `json:"recipients"`
	Sources            []QueueSource `json:"sources"`
}

type QueueRecord struct {
	QueueID                string            `json:"queue_id"`
	ArrivalFingerprint     string            `json:"arrival_fingerprint"`
	EnvelopeSender         string            `json:"envelope_sender"`
	RecipientSetDigest     string            `json:"recipient_set_digest"`
	SourceSetDigest        string            `json:"source_set_digest"`
	HoldState              HoldState         `json:"hold_state"`
	PolicyReason           Reason            `json:"policy_reason,omitempty"`
	PolicyRevisions        map[string]uint64 `json:"policy_revisions,omitempty"`
	ReconciliationAttempts uint64            `json:"reconciliation_attempts"`
	LastErrorCode          string            `json:"last_error_code,omitempty"`
	FirstSeenAt            time.Time         `json:"first_seen_at"`
	UpdatedAt              time.Time         `json:"updated_at"`
	Recipients             []string          `json:"recipients"`
	Sources                []QueueSource     `json:"sources"`
}

type QueueStore struct {
	DB  *sql.DB
	Now func() time.Time
}

type queueQueryer interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

// Register persists immutable Postfix arrival identity and authoritative
// source-object references. Repeating the exact registration is a no-op;
// queue-ID reuse with different metadata fails closed.
// Complexity: time O(r log r+s log s+b), Omega(r+s), tight
// Theta(r log r+s log s+b); auxiliary space O(r+s+b), Omega(r+s), where r is
// bounded recipients, s is bounded sources, and b is their total bytes.
func (s QueueStore) Register(ctx context.Context, in QueueRegistration) (QueueRecord, bool, error) {
	if s.DB == nil {
		return QueueRecord{}, false, errors.New("outbound queue database is unavailable")
	}
	record, err := normalizeQueueRegistration(in)
	if err != nil {
		return QueueRecord{}, false, err
	}
	now := s.now()
	record.FirstSeenAt = now
	record.UpdatedAt = now
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return QueueRecord{}, false, err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `INSERT INTO outbound_queue_messages(queue_id,arrival_fingerprint,envelope_sender,recipient_set_digest,source_set_digest,first_seen_at,updated_at) VALUES ($1,$2,$3,$4,$5,$6,$6) ON CONFLICT (queue_id) DO NOTHING`, record.QueueID, record.ArrivalFingerprint, record.EnvelopeSender, record.RecipientSetDigest, record.SourceSetDigest, now)
	if err != nil {
		return QueueRecord{}, false, err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return QueueRecord{}, false, err
	}
	created := affected == 1
	if affected > 1 {
		return QueueRecord{}, false, errors.New("outbound queue insert affected multiple records")
	}
	if created {
		if err := copyQueueRecipients(ctx, tx, record); err != nil {
			return QueueRecord{}, false, err
		}
		if err := copyQueueSources(ctx, tx, record); err != nil {
			return QueueRecord{}, false, err
		}
	}
	stored, err := loadQueueRecord(ctx, tx, record.QueueID)
	if err != nil {
		return QueueRecord{}, false, err
	}
	if !sameQueueIdentity(stored, record) {
		return QueueRecord{}, false, errors.New("Postfix queue ID is already bound to different arrival metadata")
	}
	if err := tx.Commit(); err != nil {
		return QueueRecord{}, false, err
	}
	return stored, created, nil
}

// Load returns one queue record only after recomputing both immutable set
// digests. Missing or changed child rows therefore fail closed.
// Complexity: time O(r+s+b), Omega(r+s), tight Theta(r+s+b); auxiliary space
// O(r+s+b), Omega(r+s), with the bounded variables defined by Register.
func (s QueueStore) Load(ctx context.Context, queueID string) (QueueRecord, error) {
	if s.DB == nil {
		return QueueRecord{}, errors.New("outbound queue database is unavailable")
	}
	if !validLongQueueID(queueID) {
		return QueueRecord{}, errors.New("invalid Postfix long queue ID")
	}
	return loadQueueRecord(ctx, s.DB, queueID)
}

// now supplies one UTC persistence timestamp source.
// Complexity: time O(1), Omega(1), tight Theta(1); auxiliary space O(1),
// Omega(1), tight Theta(1).
func (s QueueStore) now() time.Time {
	if s.Now != nil {
		return s.Now().UTC()
	}
	return time.Now().UTC()
}

// normalizeQueueRegistration validates and canonicalizes bounded queue
// identity before a database transaction starts.
// Complexity: time O(r log r+s log s+b), Omega(r+s), tight
// Theta(r log r+s log s+b); auxiliary space O(r+s+b), Omega(r+s).
func normalizeQueueRegistration(in QueueRegistration) (QueueRecord, error) {
	if !validLongQueueID(in.QueueID) {
		return QueueRecord{}, errors.New("invalid Postfix long queue ID")
	}
	if !validLowerHexDigest(in.ArrivalFingerprint) {
		return QueueRecord{}, errors.New("invalid queue arrival fingerprint")
	}
	sender, err := normalizeQueueSender(in.EnvelopeSender)
	if err != nil {
		return QueueRecord{}, err
	}
	if len(in.Recipients) == 0 || len(in.Recipients) > maxQueueRecipients {
		return QueueRecord{}, errors.New("outbound queue recipient limit violated")
	}
	recipientSet := make(map[string]struct{}, len(in.Recipients))
	for _, raw := range in.Recipients {
		recipient, _, err := normalizeQueueRecipient(raw)
		if err != nil {
			return QueueRecord{}, err
		}
		recipientSet[recipient] = struct{}{}
	}
	recipients := make([]string, 0, len(recipientSet))
	for recipient := range recipientSet {
		recipients = append(recipients, recipient)
	}
	sort.Strings(recipients)
	if len(in.Sources) == 0 || len(in.Sources) > maxQueueSources {
		return QueueRecord{}, errors.New("outbound queue source limit violated")
	}
	sourceSet := make(map[string]QueueSource, len(in.Sources))
	for _, source := range in.Sources {
		if !validSourceKind(source.Kind) || !validQueueObjectID(source.ObjectID) {
			return QueueRecord{}, errors.New("invalid outbound queue source")
		}
		sourceSet[string(source.Kind)+"\x00"+source.ObjectID] = source
	}
	sources := make([]QueueSource, 0, len(sourceSet))
	for _, source := range sourceSet {
		sources = append(sources, source)
	}
	sort.Slice(sources, func(i, j int) bool {
		if sources[i].Kind == sources[j].Kind {
			return sources[i].ObjectID < sources[j].ObjectID
		}
		return sources[i].Kind < sources[j].Kind
	})
	return QueueRecord{
		QueueID:            in.QueueID,
		ArrivalFingerprint: in.ArrivalFingerprint,
		EnvelopeSender:     sender,
		RecipientSetDigest: digestStrings(recipients),
		SourceSetDigest:    digestSources(sources),
		HoldState:          HoldPending,
		Recipients:         recipients,
		Sources:            sources,
	}, nil
}

// normalizeQueueSender admits the SMTP null reverse path or one canonical
// envelope address.
// Complexity: time O(n), Omega(1), tight Theta(n); auxiliary space O(n),
// Omega(1), where n is the bounded sender length.
func normalizeQueueSender(raw string) (string, error) {
	if raw == "<>" {
		return raw, nil
	}
	address, _, err := normalizeQueueRecipient(raw)
	if err != nil {
		return "", errors.New("invalid queue envelope sender")
	}
	return address, nil
}

// normalizeQueueRecipient preserves the local part and canonicalizes only the
// policy-relevant DNS domain.
// Complexity: time O(n), Omega(1), tight Theta(n); auxiliary space O(n),
// Omega(1), where n is the bounded recipient length.
func normalizeQueueRecipient(raw string) (string, string, error) {
	domain, err := recipientDomain(raw)
	if err != nil {
		return "", "", errors.New("invalid queue recipient")
	}
	trimmed := strings.TrimSpace(raw)
	at := strings.LastIndexByte(trimmed, '@')
	return trimmed[:at+1] + domain, domain, nil
}

// validLowerHexDigest recognizes the canonical SHA-256 text form.
// Complexity: time O(1), Omega(1), tight Theta(1); auxiliary space O(1),
// Omega(1), tight Theta(1), because the accepted input is exactly 64 bytes.
func validLowerHexDigest(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	for i := range value {
		if (value[i] < '0' || value[i] > '9') && (value[i] < 'a' || value[i] > 'f') {
			return false
		}
	}
	return true
}

// validSourceKind recognizes the complete queue-provenance enum.
// Complexity: time O(1), Omega(1), tight Theta(1); auxiliary space O(1),
// Omega(1), tight Theta(1).
func validSourceKind(kind SourceKind) bool {
	switch kind {
	case SourceAuthenticatedMailbox, SourceEnvelopeSender, SourceSystemSender, SourceAlias, SourceForward, SourceList, SourceCatchAll:
		return true
	default:
		return false
	}
}

// validQueueObjectID rejects trimming ambiguity, invalid UTF-8, controls, and
// identifiers outside the fixed persistence bound.
// Complexity: time O(n), Omega(1), tight Theta(n) for valid input; auxiliary
// space O(1), Omega(1), tight Theta(1), where n is the bounded ID length.
func validQueueObjectID(id string) bool {
	if len(id) == 0 || len(id) > maxQueueObjectID || !utf8.ValidString(id) || strings.TrimSpace(id) != id {
		return false
	}
	for _, r := range id {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

// copyQueueRecipients streams canonical recipients through PostgreSQL COPY,
// avoiding one SQL round trip per row.
// Complexity: time O(r*b), Omega(r), tight Theta(r*b); auxiliary space O(1),
// Omega(1), excluding bounded driver buffering, where r is recipients and b
// is maximum address length.
func copyQueueRecipients(ctx context.Context, tx *sql.Tx, record QueueRecord) error {
	stmt, err := tx.PrepareContext(ctx, pq.CopyIn("outbound_queue_recipients", "queue_id", "recipient", "recipient_domain"))
	if err != nil {
		return err
	}
	for _, recipient := range record.Recipients {
		_, domain, err := normalizeQueueRecipient(recipient)
		if err != nil {
			stmt.Close()
			return err
		}
		if _, err := stmt.ExecContext(ctx, record.QueueID, recipient, domain); err != nil {
			stmt.Close()
			return err
		}
	}
	if _, err := stmt.ExecContext(ctx); err != nil {
		stmt.Close()
		return err
	}
	return stmt.Close()
}

// copyQueueSources streams canonical provenance through PostgreSQL COPY.
// Complexity: time O(s*b), Omega(s), tight Theta(s*b); auxiliary space O(1),
// Omega(1), excluding bounded driver buffering, where s is sources and b is
// maximum object-ID length.
func copyQueueSources(ctx context.Context, tx *sql.Tx, record QueueRecord) error {
	stmt, err := tx.PrepareContext(ctx, pq.CopyIn("outbound_queue_sources", "queue_id", "source_kind", "object_id"))
	if err != nil {
		return err
	}
	for _, source := range record.Sources {
		if _, err := stmt.ExecContext(ctx, record.QueueID, string(source.Kind), source.ObjectID); err != nil {
			stmt.Close()
			return err
		}
	}
	if _, err := stmt.ExecContext(ctx); err != nil {
		stmt.Close()
		return err
	}
	return stmt.Close()
}

// loadQueueRecord reads one parent and its bounded child sets, then validates
// canonical forms and stored digests before returning them.
// Complexity: time O(r+s+b), Omega(r+s), tight Theta(r+s+b); auxiliary space
// O(r+s+b), Omega(r+s), with the bounded variables defined by Register.
func loadQueueRecord(ctx context.Context, queryer queueQueryer, queueID string) (QueueRecord, error) {
	var record QueueRecord
	var reason, lastError sql.NullString
	var encodedRevisions []byte
	var attempts int64
	if err := queryer.QueryRowContext(ctx, `SELECT queue_id,arrival_fingerprint,envelope_sender,recipient_set_digest,source_set_digest,hold_state,policy_reason,policy_revisions_json,reconciliation_attempts,last_error_code,first_seen_at,updated_at FROM outbound_queue_messages WHERE queue_id=$1`, queueID).Scan(&record.QueueID, &record.ArrivalFingerprint, &record.EnvelopeSender, &record.RecipientSetDigest, &record.SourceSetDigest, &record.HoldState, &reason, &encodedRevisions, &attempts, &lastError, &record.FirstSeenAt, &record.UpdatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return QueueRecord{}, errors.New("outbound queue record not found")
		}
		return QueueRecord{}, err
	}
	canonicalSender, senderErr := normalizeQueueSender(record.EnvelopeSender)
	if record.QueueID != queueID || !validLongQueueID(record.QueueID) || senderErr != nil || canonicalSender != record.EnvelopeSender || attempts < 0 || !validHoldState(record.HoldState) || !validLowerHexDigest(record.ArrivalFingerprint) || !validLowerHexDigest(record.RecipientSetDigest) || !validLowerHexDigest(record.SourceSetDigest) || record.FirstSeenAt.IsZero() || record.UpdatedAt.Before(record.FirstSeenAt) {
		return QueueRecord{}, errors.New("stored outbound queue state is invalid")
	}
	record.ReconciliationAttempts = uint64(attempts)
	if reason.Valid {
		record.PolicyReason = Reason(reason.String)
		if !validQueueReason(record.PolicyReason) {
			return QueueRecord{}, errors.New("stored outbound queue reason is invalid")
		}
	}
	if err := json.Unmarshal(encodedRevisions, &record.PolicyRevisions); err != nil {
		return QueueRecord{}, errors.New("stored outbound queue policy revisions are invalid")
	}
	if len(record.PolicyRevisions) > 0 {
		canonical, _, err := canonicalPolicyRevisions(record.PolicyRevisions)
		if err != nil || !revisionMapsEqual(record.PolicyRevisions, canonical) {
			return QueueRecord{}, errors.New("stored outbound queue policy revisions are invalid")
		}
	}
	if !validQueuePolicyState(record.HoldState, reason.Valid, record.PolicyReason, record.PolicyRevisions) {
		return QueueRecord{}, errors.New("stored outbound queue policy state is invalid")
	}
	if lastError.Valid {
		record.LastErrorCode = lastError.String
		if !validQueueErrorCode(record.LastErrorCode) {
			return QueueRecord{}, errors.New("stored outbound queue error code is invalid")
		}
	}
	recipientRows, err := queryer.QueryContext(ctx, `SELECT recipient,recipient_domain FROM outbound_queue_recipients WHERE queue_id=$1 ORDER BY recipient`, queueID)
	if err != nil {
		return QueueRecord{}, err
	}
	for recipientRows.Next() {
		if len(record.Recipients) >= maxQueueRecipients {
			recipientRows.Close()
			return QueueRecord{}, errors.New("stored outbound queue recipient limit exceeded")
		}
		var recipient, storedDomain string
		if err := recipientRows.Scan(&recipient, &storedDomain); err != nil {
			recipientRows.Close()
			return QueueRecord{}, err
		}
		canonical, domain, err := normalizeQueueRecipient(recipient)
		if err != nil || canonical != recipient || domain != storedDomain {
			recipientRows.Close()
			return QueueRecord{}, errors.New("stored outbound queue recipient is invalid")
		}
		record.Recipients = append(record.Recipients, recipient)
	}
	if err := recipientRows.Err(); err != nil {
		recipientRows.Close()
		return QueueRecord{}, err
	}
	if err := recipientRows.Close(); err != nil {
		return QueueRecord{}, err
	}
	sourceRows, err := queryer.QueryContext(ctx, `SELECT source_kind,object_id FROM outbound_queue_sources WHERE queue_id=$1 ORDER BY source_kind,object_id`, queueID)
	if err != nil {
		return QueueRecord{}, err
	}
	for sourceRows.Next() {
		if len(record.Sources) >= maxQueueSources {
			sourceRows.Close()
			return QueueRecord{}, errors.New("stored outbound queue source limit exceeded")
		}
		var source QueueSource
		if err := sourceRows.Scan(&source.Kind, &source.ObjectID); err != nil {
			sourceRows.Close()
			return QueueRecord{}, err
		}
		if !validSourceKind(source.Kind) || !validQueueObjectID(source.ObjectID) {
			sourceRows.Close()
			return QueueRecord{}, errors.New("stored outbound queue source is invalid")
		}
		record.Sources = append(record.Sources, source)
	}
	if err := sourceRows.Err(); err != nil {
		sourceRows.Close()
		return QueueRecord{}, err
	}
	if err := sourceRows.Close(); err != nil {
		return QueueRecord{}, err
	}
	if len(record.Recipients) == 0 || len(record.Sources) == 0 || digestStrings(record.Recipients) != record.RecipientSetDigest || digestSources(record.Sources) != record.SourceSetDigest {
		return QueueRecord{}, errors.New("stored outbound queue provenance digest mismatch")
	}
	record.FirstSeenAt = record.FirstSeenAt.UTC()
	record.UpdatedAt = record.UpdatedAt.UTC()
	return record, nil
}

// sameQueueIdentity compares all immutable parent identity fields; child-set
// equality is represented by their validated digests.
// Complexity: time O(1), Omega(1), tight Theta(1); auxiliary space O(1),
// Omega(1), tight Theta(1).
func sameQueueIdentity(left, right QueueRecord) bool {
	return left.QueueID == right.QueueID && left.ArrivalFingerprint == right.ArrivalFingerprint && left.EnvelopeSender == right.EnvelopeSender && left.RecipientSetDigest == right.RecipientSetDigest && left.SourceSetDigest == right.SourceSetDigest
}

// validHoldState recognizes the complete durable queue state machine.
// Complexity: time O(1), Omega(1), tight Theta(1); auxiliary space O(1),
// Omega(1), tight Theta(1).
func validHoldState(state HoldState) bool {
	switch state {
	case HoldPending, HoldRequired, HoldReconciling, HoldApplied, HoldReconciliationError, HoldReleased:
		return true
	default:
		return false
	}
}

// validQueueReason recognizes reasons that can require a whole-message hold.
// Complexity: time O(1), Omega(1), tight Theta(1); auxiliary space O(1),
// Omega(1), tight Theta(1).
func validQueueReason(reason Reason) bool {
	return reason == ReasonPolicyHold || reason == ReasonCrossDomainConflict || reason == ReasonUnavailable
}

// validQueuePolicyState checks the semantic relation between durable hold
// state, reason, and the revisions that caused it.
// Complexity: time O(1), Omega(1), tight Theta(1); auxiliary space O(1),
// Omega(1), tight Theta(1).
func validQueuePolicyState(state HoldState, hasReason bool, reason Reason, revisions map[string]uint64) bool {
	if state == HoldPending {
		return !hasReason && len(revisions) == 0
	}
	return hasReason && validQueueReason(reason) && len(revisions) > 0
}

// validQueueErrorCode recognizes the bounded machine-readable diagnostic form.
// Complexity: time O(n), Omega(1), tight Theta(n) for valid input; auxiliary
// space O(1), Omega(1), tight Theta(1), where n is at most 128 bytes.
func validQueueErrorCode(code string) bool {
	if len(code) == 0 || len(code) > 128 {
		return false
	}
	for i := range code {
		if (code[i] < 'a' || code[i] > 'z') && (code[i] < '0' || code[i] > '9') && code[i] != '_' {
			return false
		}
	}
	return true
}

// digestStrings hashes an ordered string set with explicit length framing.
// Complexity: time O(b), Omega(n), tight Theta(b); auxiliary space O(1),
// Omega(1), tight Theta(1), where n is values and b is their total bytes.
func digestStrings(values []string) string {
	hash := sha256.New()
	var size [8]byte
	for _, value := range values {
		binary.BigEndian.PutUint64(size[:], uint64(len(value)))
		hash.Write(size[:])
		hash.Write([]byte(value))
	}
	return hex.EncodeToString(hash.Sum(nil))
}

// digestSources hashes an ordered source set with independent kind/ID frames.
// Complexity: time O(b), Omega(n), tight Theta(b); auxiliary space O(1),
// Omega(1), tight Theta(1), where n is sources and b is their total bytes.
func digestSources(sources []QueueSource) string {
	hash := sha256.New()
	var size [8]byte
	for _, source := range sources {
		kind := string(source.Kind)
		binary.BigEndian.PutUint64(size[:], uint64(len(kind)))
		hash.Write(size[:])
		hash.Write([]byte(kind))
		binary.BigEndian.PutUint64(size[:], uint64(len(source.ObjectID)))
		hash.Write(size[:])
		hash.Write([]byte(source.ObjectID))
	}
	return hex.EncodeToString(hash.Sum(nil))
}
