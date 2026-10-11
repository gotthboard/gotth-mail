package outboundpolicy

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/lib/pq"

	"forgejo/gotthboard/gotth-mail/internal/generatedmsgid"
)

const (
	FinalQueueStatePrepared = "prepared"
	FinalQueueStateBound    = "bound"
	maxSignedArtifactBytes  = 72796392
)

var finalQueueFingerprintRE = regexp.MustCompile(`^([0-9a-f]{40}|[0-9a-f]{64})$`)

type FinalQueueStore struct {
	DB         *sql.DB
	InstanceID string
	Now        func() time.Time
}

type FinalQueueArtifact struct {
	ArtifactID         string
	SignedMessageID    string
	SignedDate         time.Time
	ContentSHA256      string
	ContentBytes       int64
	LocalIdentityID    string
	LocalMailboxID     string
	EnvelopeSender     string
	NullEnvelopeSender bool
	SignerIdentityID   string
	SignerFingerprint  string
	sourceSetDigest    string
	recipientSetDigest string
	provenanceDigest   string
	State              string
	PreparedAt         time.Time
	UpdatedAt          time.Time
	ExpiresAt          time.Time
	Recipients         []string
	Sources            []FinalQueueSource
}

type FinalQueueSource struct {
	QueueSource
	Revision int64
}

type FinalQueueBinding struct {
	ArtifactID         string
	InstanceID         string
	QueueID            string
	ArrivalFingerprint string
	BoundAt            time.Time
}

type FinalQueueBoundArtifact struct {
	FinalQueueArtifact
	InstanceID         string
	QueueID            string
	ArrivalFingerprint string
	BoundAt            time.Time
	Queue              QueueRecord
}

// PrepareFinalQueueArtifact persists immutable pre-queue signed artifact intent.
// It canonicalizes recipients, sender and source membership with the same queue
// helpers used by QueueStore; callers never provide domains or digests. Same
// artifact IDs are serialized by a transaction-scoped PostgreSQL advisory lock
// before wall-clock defaults are read; advisory hash collisions can serialize
// unrelated artifact IDs, and SQL/advisory lock wait time is part of Q.
// Complexity: time O(r log r+s log s+b+Q), Omega(r+s), tight Theta is not established because Q is delegated SQL and lock wait work; auxiliary space O(r+s+b), Omega(r+s), tight Theta(r+s+b), where r is recipients, s sources, and b bounded field bytes.
func (s FinalQueueStore) PrepareFinalQueueArtifact(ctx context.Context, in FinalQueueArtifact) (FinalQueueArtifact, error) {
	if s.DB == nil {
		return FinalQueueArtifact{}, errors.New("final queue database is unavailable")
	}
	if !validQueueInstanceID(in.ArtifactID) {
		return FinalQueueArtifact{}, errors.New("invalid final queue artifact identity")
	}
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return FinalQueueArtifact{}, err
	}
	defer tx.Rollback()
	if err := lockFinalQueueArtifactPrepareTx(ctx, tx, in.ArtifactID); err != nil {
		return FinalQueueArtifact{}, err
	}
	existing, ok, err := loadFinalQueueArtifactTx(ctx, tx, in.ArtifactID, true)
	if err != nil {
		return FinalQueueArtifact{}, err
	}
	if ok {
		replay := in
		replay.PreparedAt = existing.PreparedAt
		replay.UpdatedAt = existing.PreparedAt
		prepared, err := canonicalFinalQueueArtifact(replay)
		if err != nil {
			return FinalQueueArtifact{}, err
		}
		if !sameFinalQueueIntent(existing.FinalQueueArtifact, prepared) {
			return FinalQueueArtifact{}, errors.New("final queue artifact prepare mismatch")
		}
		if err := tx.Commit(); err != nil {
			return FinalQueueArtifact{}, err
		}
		return existing.FinalQueueArtifact, nil
	}
	in = s.defaultPreparedTimes(in)
	prepared, err := canonicalFinalQueueArtifact(in)
	if err != nil {
		return FinalQueueArtifact{}, err
	}
	created, err := insertFinalQueueArtifactParentTx(ctx, tx, prepared)
	if err != nil {
		return FinalQueueArtifact{}, err
	}
	if !created {
		return FinalQueueArtifact{}, errors.New("final queue artifact prepare lost serialization")
	}
	if err := copyFinalQueueRecipients(ctx, tx, prepared); err != nil {
		return FinalQueueArtifact{}, err
	}
	if err := copyFinalQueueSources(ctx, tx, prepared); err != nil {
		return FinalQueueArtifact{}, err
	}
	existing, ok, err = loadFinalQueueArtifactTx(ctx, tx, prepared.ArtifactID, true)
	if err != nil {
		return FinalQueueArtifact{}, err
	}
	if !ok {
		return FinalQueueArtifact{}, errors.New("final queue artifact prepare did not persist")
	}
	if !sameFinalQueueIntent(existing.FinalQueueArtifact, prepared) {
		return FinalQueueArtifact{}, errors.New("final queue artifact prepare mismatch")
	}
	if err := tx.Commit(); err != nil {
		return FinalQueueArtifact{}, err
	}
	return existing.FinalQueueArtifact, nil
}

// BindFinalQueueArtifact binds prepared intent to an already observed queue.
// QueueStore.Load remains delivery authority; binding compares fingerprint,
// canonical sender/null mapping, recipient digest and source digest before SQL.
// Complexity: time O(r log r+s log s+b+Q), Omega(r+s), tight Theta is not established because Q is delegated SQL; auxiliary space O(r+s+b), Omega(r+s), tight Theta(r+s+b), where r/s/b match prepared intent and observed queue bounds. The artifact reload path recanonicalizes maps and sorts child rows in Go; Q does not hide that work.
func (s FinalQueueStore) BindFinalQueueArtifact(ctx context.Context, in FinalQueueBinding) (FinalQueueBoundArtifact, error) {
	if s.DB == nil {
		return FinalQueueBoundArtifact{}, errors.New("final queue database is unavailable")
	}
	if !validQueueInstanceID(s.InstanceID) || in.InstanceID != s.InstanceID {
		return FinalQueueBoundArtifact{}, errors.New("invalid final queue instance")
	}
	if !validQueueBinding(in) {
		return FinalQueueBoundArtifact{}, errors.New("invalid final queue binding")
	}
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return FinalQueueBoundArtifact{}, err
	}
	defer tx.Rollback()
	artifact, ok, err := loadFinalQueueArtifactTx(ctx, tx, in.ArtifactID, true)
	if err != nil {
		return FinalQueueBoundArtifact{}, err
	}
	if !ok {
		return FinalQueueBoundArtifact{}, errors.New("final queue artifact is not prepared")
	}
	var existing FinalQueueBinding
	err = tx.QueryRowContext(ctx, `SELECT instance_id, queue_id, artifact_id, arrival_fingerprint, bound_at FROM final_queue_bindings WHERE artifact_id=$1`, in.ArtifactID).Scan(&existing.InstanceID, &existing.QueueID, &existing.ArtifactID, &existing.ArrivalFingerprint, &existing.BoundAt)
	if err == nil {
		if existing.InstanceID == in.InstanceID && existing.QueueID == in.QueueID && existing.ArrivalFingerprint == in.ArrivalFingerprint {
			queue, err := loadQueueRecordForShare(ctx, tx, in.QueueID)
			if err != nil {
				return FinalQueueBoundArtifact{}, err
			}
			if err := artifactMatchesQueue(artifact.FinalQueueArtifact, queue, in.ArrivalFingerprint); err != nil {
				return FinalQueueBoundArtifact{}, err
			}
			artifact.InstanceID = existing.InstanceID
			artifact.QueueID = existing.QueueID
			artifact.ArrivalFingerprint = existing.ArrivalFingerprint
			artifact.BoundAt = canonicalPostgresTime(existing.BoundAt)
			artifact.Queue = queue
			if err := validateBoundFinalQueueArtifact(artifact); err != nil {
				return FinalQueueBoundArtifact{}, err
			}
			if err := tx.Commit(); err != nil {
				return FinalQueueBoundArtifact{}, err
			}
			return artifact, nil
		}
		return FinalQueueBoundArtifact{}, errors.New("final queue artifact already bound")
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return FinalQueueBoundArtifact{}, err
	}
	if artifact.State != FinalQueueStatePrepared {
		return FinalQueueBoundArtifact{}, errors.New("final queue artifact is not prepared")
	}
	if in.BoundAt.IsZero() {
		in.BoundAt = s.now()
	} else {
		in.BoundAt = canonicalPostgresTime(in.BoundAt)
	}
	if in.BoundAt.Before(artifact.PreparedAt) || !in.BoundAt.Before(artifact.ExpiresAt) {
		return FinalQueueBoundArtifact{}, errors.New("invalid final queue bound time")
	}
	queue, err := loadQueueRecordForShare(ctx, tx, in.QueueID)
	if err != nil {
		return FinalQueueBoundArtifact{}, err
	}
	if err := artifactMatchesQueue(artifact.FinalQueueArtifact, queue, in.ArrivalFingerprint); err != nil {
		return FinalQueueBoundArtifact{}, err
	}
	var artifactID string
	err = tx.QueryRowContext(ctx, `SELECT artifact_id FROM final_queue_bindings WHERE queue_id=$1`, in.QueueID).Scan(&artifactID)
	if err == nil {
		return FinalQueueBoundArtifact{}, errors.New("final queue observed queue already bound")
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return FinalQueueBoundArtifact{}, err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO final_queue_bindings(instance_id, queue_id, artifact_id, arrival_fingerprint, bound_at) VALUES ($1,$2,$3,$4,$5)`, in.InstanceID, in.QueueID, in.ArtifactID, in.ArrivalFingerprint, in.BoundAt); err != nil {
		return FinalQueueBoundArtifact{}, err
	}
	result, err := tx.ExecContext(ctx, `UPDATE final_queue_artifacts SET state='bound', updated_at=$2 WHERE artifact_id=$1 AND state='prepared'`, in.ArtifactID, in.BoundAt)
	if err != nil {
		return FinalQueueBoundArtifact{}, err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return FinalQueueBoundArtifact{}, err
	}
	if affected != 1 {
		return FinalQueueBoundArtifact{}, errors.New("final queue artifact state transition failed")
	}
	artifact.InstanceID = in.InstanceID
	artifact.QueueID = in.QueueID
	artifact.ArrivalFingerprint = in.ArrivalFingerprint
	artifact.BoundAt = in.BoundAt
	artifact.Queue = queue
	artifact.State = FinalQueueStateBound
	artifact.UpdatedAt = in.BoundAt
	if err := validateBoundFinalQueueArtifact(artifact); err != nil {
		return FinalQueueBoundArtifact{}, err
	}
	if err := tx.Commit(); err != nil {
		return FinalQueueBoundArtifact{}, err
	}
	return artifact, nil
}

// LookupFinalQueueBinding reloads and revalidates artifact intent plus the
// QueueStore record. Any deleted/tampered child row or changed observed queue
// fails closed instead of returning partial authority.
// Complexity: time O(r log r+s log s+b+Q), Omega(r+s), tight Theta is not established because Q is delegated SQL; auxiliary space O(r+s+b), Omega(r+s), tight Theta(r+s+b), where r/s/b match prepared intent and observed queue bounds. The artifact reload path recanonicalizes maps and sorts child rows in Go; Q does not hide that work.
func (s FinalQueueStore) LookupFinalQueueBinding(ctx context.Context, instanceID, queueID string) (FinalQueueBoundArtifact, error) {
	if s.DB == nil {
		return FinalQueueBoundArtifact{}, errors.New("final queue database is unavailable")
	}
	if !validQueueInstanceID(s.InstanceID) || instanceID != s.InstanceID {
		return FinalQueueBoundArtifact{}, errors.New("invalid final queue instance")
	}
	if !validQueueInstanceID(instanceID) || !validLongQueueID(queueID) {
		return FinalQueueBoundArtifact{}, errors.New("invalid final queue lookup key")
	}
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return FinalQueueBoundArtifact{}, err
	}
	defer tx.Rollback()
	var binding FinalQueueBinding
	err = tx.QueryRowContext(ctx, `SELECT instance_id, queue_id, artifact_id, arrival_fingerprint, bound_at FROM final_queue_bindings WHERE instance_id=$1 AND queue_id=$2`, instanceID, queueID).Scan(&binding.InstanceID, &binding.QueueID, &binding.ArtifactID, &binding.ArrivalFingerprint, &binding.BoundAt)
	if err != nil {
		return FinalQueueBoundArtifact{}, err
	}
	artifact, ok, err := loadFinalQueueArtifactTx(ctx, tx, binding.ArtifactID, false)
	if err != nil {
		return FinalQueueBoundArtifact{}, err
	}
	artifact.InstanceID = binding.InstanceID
	artifact.QueueID = binding.QueueID
	artifact.ArrivalFingerprint = binding.ArrivalFingerprint
	artifact.BoundAt = canonicalPostgresTime(binding.BoundAt)
	if !ok || artifact.State != FinalQueueStateBound {
		return FinalQueueBoundArtifact{}, errors.New("stored final queue binding is invalid")
	}
	queue, err := loadQueueRecordForShare(ctx, tx, binding.QueueID)
	if err != nil {
		return FinalQueueBoundArtifact{}, err
	}
	if err := artifactMatchesQueue(artifact.FinalQueueArtifact, queue, binding.ArrivalFingerprint); err != nil {
		return FinalQueueBoundArtifact{}, err
	}
	artifact.Queue = queue
	if err := validateBoundFinalQueueArtifact(artifact); err != nil {
		return FinalQueueBoundArtifact{}, err
	}
	if err := tx.Commit(); err != nil {
		return FinalQueueBoundArtifact{}, err
	}
	return artifact, nil
}

// defaultPreparedTimes supplies stable UTC timestamps before validation.
// Complexity: time O(1), Omega(1), tight Theta(1); auxiliary space O(1),
// Omega(1), tight Theta(1).
func (s FinalQueueStore) defaultPreparedTimes(in FinalQueueArtifact) FinalQueueArtifact {
	if in.PreparedAt.IsZero() {
		in.PreparedAt = s.now()
	}
	in.PreparedAt = canonicalPostgresTime(in.PreparedAt)
	in.UpdatedAt = in.PreparedAt
	return in
}

// now returns one UTC wall-clock value for persistence defaults.
// Complexity: time O(1), Omega(1), tight Theta(1); auxiliary space O(1),
// Omega(1), tight Theta(1).
func (s FinalQueueStore) now() time.Time {
	if s.Now != nil {
		return canonicalPostgresTime(s.Now())
	}
	return canonicalPostgresTime(time.Now())
}

// canonicalPostgresTime matches PostgreSQL timestamp microsecond precision before validation, digesting and comparison.
// Complexity: time O(1), Omega(1), tight Theta(1); auxiliary space O(1), Omega(1), tight Theta(1).
func canonicalPostgresTime(value time.Time) time.Time {
	if value.IsZero() {
		return time.Time{}
	}
	return value.UTC().Round(time.Microsecond)
}

// canonicalFinalQueueArtifact validates caller intent and derives all digests.
// Complexity: time O(r log r+s log s+b), Omega(r+s), tight Theta(r log r+s log s+b); auxiliary space O(r+s+b), Omega(r+s), tight Theta(r+s+b), where r/s/b are bounded recipients/sources/bytes.
func canonicalFinalQueueArtifact(in FinalQueueArtifact) (FinalQueueArtifact, error) {
	if !validQueueInstanceID(in.ArtifactID) || !validGeneratedSignedMessageID(in.SignedMessageID) || in.SignedDate.IsZero() || !validLowerHexDigest(in.ContentSHA256) || in.ContentBytes <= 0 || in.ContentBytes > maxSignedArtifactBytes {
		return FinalQueueArtifact{}, errors.New("invalid final queue artifact identity")
	}
	if !validQueueObjectID(in.LocalIdentityID) || !validQueueObjectID(in.LocalMailboxID) || !validQueueObjectID(in.SignerIdentityID) || !finalQueueFingerprintRE.MatchString(in.SignerFingerprint) {
		return FinalQueueArtifact{}, errors.New("invalid final queue local identity metadata")
	}
	sender, err := normalizeQueueSender(in.EnvelopeSender)
	if err != nil {
		return FinalQueueArtifact{}, err
	}
	if in.NullEnvelopeSender != (sender == "<>") {
		return FinalQueueArtifact{}, errors.New("invalid final queue envelope null mapping")
	}
	in.SignedDate = canonicalPostgresTime(in.SignedDate)
	in.PreparedAt = canonicalPostgresTime(in.PreparedAt)
	in.UpdatedAt = canonicalPostgresTime(in.UpdatedAt)
	in.ExpiresAt = canonicalPostgresTime(in.ExpiresAt)
	if in.PreparedAt.IsZero() || in.ExpiresAt.IsZero() || in.SignedDate.After(in.PreparedAt) || !in.ExpiresAt.After(in.PreparedAt) {
		return FinalQueueArtifact{}, errors.New("invalid final queue prepare/expiry time")
	}
	recipients, err := canonicalQueueRecipients(in.Recipients)
	if err != nil || len(recipients) == 0 || len(recipients) > maxQueueRecipients {
		return FinalQueueArtifact{}, errors.New("invalid final queue recipients")
	}
	sources, queueSources, err := canonicalFinalQueueSources(in.Sources)
	if err != nil {
		return FinalQueueArtifact{}, err
	}
	in.UpdatedAt = in.PreparedAt
	in.EnvelopeSender = sender
	in.SignerFingerprint = strings.ToLower(in.SignerFingerprint)
	in.State = FinalQueueStatePrepared
	in.Recipients = recipients
	in.Sources = sources
	in.recipientSetDigest = digestStrings(recipients)
	in.sourceSetDigest = digestSources(queueSources)
	in.provenanceDigest = digestFinalQueueProvenance(in)
	return in, nil
}

// canonicalFinalQueueSources validates revision-bearing sources and returns the
// QueueStore membership projection used for observed-queue comparison.
// Complexity: time O(s log s+b), Omega(s), tight Theta(s log s+b); auxiliary space O(s+b), Omega(s), tight Theta(s+b), where s is sources and b their bytes.
func canonicalFinalQueueSources(raw []FinalQueueSource) ([]FinalQueueSource, []QueueSource, error) {
	if len(raw) == 0 || len(raw) > maxQueueSources {
		return nil, nil, errors.New("invalid final queue sources")
	}
	set := make(map[string]FinalQueueSource, len(raw))
	for _, source := range raw {
		if !validSourceKind(source.Kind) || !validQueueObjectID(source.ObjectID) || source.Revision <= 0 {
			return nil, nil, errors.New("invalid final queue source")
		}
		key := string(source.Kind) + "\x00" + source.ObjectID
		if existing, ok := set[key]; ok {
			if existing.Revision != source.Revision {
				return nil, nil, errors.New("conflicting final queue source revision")
			}
			continue
		}
		set[key] = source
	}
	out := make([]FinalQueueSource, 0, len(set))
	for _, source := range set {
		out = append(out, source)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Kind == out[j].Kind {
			return out[i].ObjectID < out[j].ObjectID
		}
		return out[i].Kind < out[j].Kind
	})
	queueSources := make([]QueueSource, len(out))
	for i, source := range out {
		queueSources[i] = source.QueueSource
	}
	return out, queueSources, nil
}

// lockFinalQueueArtifactPrepareTx serializes prepare/create decisions for one validated artifact ID.
// PostgreSQL hashes the bounded ID to an advisory key; hash collisions only add
// conservative same-transaction serialization. No other final-queue path takes
// this advisory lock after row locks, so the order is advisory lock then row lock.
// Complexity: time O(b+Q), Omega(1), tight Theta is not established because Q is delegated SQL and lock wait work; auxiliary space O(1), Omega(1), tight Theta(1).
func lockFinalQueueArtifactPrepareTx(ctx context.Context, tx *sql.Tx, artifactID string) error {
	_, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1::text, 0))`, artifactID)
	return err
}

// insertFinalQueueArtifactParentTx writes one canonical artifact parent row.
// Complexity: time O(b+Q), Omega(1), tight Theta is not established because Q is delegated SQL work; auxiliary space O(1), Omega(1), tight Theta(1).
func insertFinalQueueArtifactParentTx(ctx context.Context, tx *sql.Tx, in FinalQueueArtifact) (bool, error) {
	result, err := tx.ExecContext(ctx, `INSERT INTO final_queue_artifacts(artifact_id, signed_message_id, signed_date, content_sha256, content_bytes, local_identity_id, local_mailbox_id, envelope_sender, null_envelope_sender, signer_identity_id, signer_fingerprint, source_set_digest, recipient_set_digest, provenance_digest, state, prepared_at, updated_at, expires_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,'prepared',$15,$16,$17) ON CONFLICT (artifact_id) DO NOTHING`, in.ArtifactID, in.SignedMessageID, in.SignedDate, in.ContentSHA256, in.ContentBytes, in.LocalIdentityID, in.LocalMailboxID, in.EnvelopeSender, in.NullEnvelopeSender, in.SignerIdentityID, in.SignerFingerprint, in.sourceSetDigest, in.recipientSetDigest, in.provenanceDigest, in.PreparedAt, in.UpdatedAt, in.ExpiresAt)
	if err != nil {
		return false, err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return false, err
	}
	if affected > 1 {
		return false, errors.New("final queue artifact insert affected multiple records")
	}
	return affected == 1, nil
}

// copyFinalQueueRecipients streams canonical recipient intent through PostgreSQL COPY inside the caller transaction.
// Complexity: time O(r*b+Q), Omega(r), tight Theta is not established because Q is delegated COPY work; auxiliary space O(1), Omega(1), tight Theta(1) excluding bounded driver buffers.
func copyFinalQueueRecipients(ctx context.Context, tx *sql.Tx, in FinalQueueArtifact) error {
	stmt, err := tx.PrepareContext(ctx, pq.CopyIn("final_queue_recipients", "artifact_id", "recipient", "recipient_domain", "ordinal"))
	if err != nil {
		return err
	}
	for i, recipient := range in.Recipients {
		_, domain, err := normalizeQueueRecipient(recipient)
		if err != nil {
			stmt.Close()
			return err
		}
		if _, err := stmt.ExecContext(ctx, in.ArtifactID, recipient, domain, i); err != nil {
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

// copyFinalQueueSources streams canonical source intent through PostgreSQL COPY inside the caller transaction.
// Complexity: time O(s*b+Q), Omega(s), tight Theta is not established because Q is delegated COPY work; auxiliary space O(1), Omega(1), tight Theta(1) excluding bounded driver buffers.
func copyFinalQueueSources(ctx context.Context, tx *sql.Tx, in FinalQueueArtifact) error {
	stmt, err := tx.PrepareContext(ctx, pq.CopyIn("final_queue_sources", "artifact_id", "source_kind", "object_id", "revision", "ordinal"))
	if err != nil {
		return err
	}
	for i, source := range in.Sources {
		if _, err := stmt.ExecContext(ctx, in.ArtifactID, string(source.Kind), source.ObjectID, source.Revision, i); err != nil {
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

// loadFinalQueueArtifactTx reads and revalidates one artifact plus child sets.
// Complexity: time O(r log r+s log s+b+Q), Omega(r+s), tight Theta is not established because Q is delegated SQL; auxiliary space O(r+s+b), Omega(r+s), tight Theta(r+s+b), where r/s/b are loaded child rows/bytes. Validation recanonicalizes, maps, and sorts child rows in Go; Q does not hide that work.
func loadFinalQueueArtifactTx(ctx context.Context, tx *sql.Tx, artifactID string, lock bool) (FinalQueueBoundArtifact, bool, error) {
	query := `SELECT artifact_id, signed_message_id, signed_date, content_sha256, content_bytes, local_identity_id, local_mailbox_id, envelope_sender, null_envelope_sender, signer_identity_id, signer_fingerprint, source_set_digest, recipient_set_digest, provenance_digest, state, prepared_at, updated_at, expires_at FROM final_queue_artifacts WHERE artifact_id=$1`
	if lock {
		query += " FOR UPDATE"
	}
	var out FinalQueueBoundArtifact
	err := tx.QueryRowContext(ctx, query, artifactID).Scan(&out.ArtifactID, &out.SignedMessageID, &out.SignedDate, &out.ContentSHA256, &out.ContentBytes, &out.LocalIdentityID, &out.LocalMailboxID, &out.EnvelopeSender, &out.NullEnvelopeSender, &out.SignerIdentityID, &out.SignerFingerprint, &out.sourceSetDigest, &out.recipientSetDigest, &out.provenanceDigest, &out.State, &out.PreparedAt, &out.UpdatedAt, &out.ExpiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return FinalQueueBoundArtifact{}, false, nil
	}
	if err != nil {
		return FinalQueueBoundArtifact{}, false, err
	}
	rows, err := tx.QueryContext(ctx, `SELECT recipient, recipient_domain, ordinal FROM final_queue_recipients WHERE artifact_id=$1 ORDER BY ordinal`, artifactID)
	if err != nil {
		return FinalQueueBoundArtifact{}, false, err
	}
	lastRecipient := ""
	for rows.Next() {
		if len(out.Recipients) >= maxQueueRecipients {
			rows.Close()
			return FinalQueueBoundArtifact{}, false, errors.New("stored final queue recipient limit exceeded")
		}
		var recipient, storedDomain string
		var ordinal int
		if err := rows.Scan(&recipient, &storedDomain, &ordinal); err != nil {
			rows.Close()
			return FinalQueueBoundArtifact{}, false, err
		}
		canonical, domain, err := normalizeQueueRecipient(recipient)
		if err != nil || canonical != recipient || domain != storedDomain || ordinal != len(out.Recipients) || (lastRecipient != "" && recipient <= lastRecipient) {
			rows.Close()
			return FinalQueueBoundArtifact{}, false, errors.New("stored final queue recipient is invalid")
		}
		lastRecipient = recipient
		out.Recipients = append(out.Recipients, recipient)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return FinalQueueBoundArtifact{}, false, err
	}
	if err := rows.Close(); err != nil {
		return FinalQueueBoundArtifact{}, false, err
	}
	rows, err = tx.QueryContext(ctx, `SELECT source_kind, object_id, revision, ordinal FROM final_queue_sources WHERE artifact_id=$1 ORDER BY ordinal`, artifactID)
	if err != nil {
		return FinalQueueBoundArtifact{}, false, err
	}
	var lastSource string
	for rows.Next() {
		if len(out.Sources) >= maxQueueSources {
			rows.Close()
			return FinalQueueBoundArtifact{}, false, errors.New("stored final queue source limit exceeded")
		}
		var source FinalQueueSource
		var ordinal int
		if err := rows.Scan(&source.Kind, &source.ObjectID, &source.Revision, &ordinal); err != nil {
			rows.Close()
			return FinalQueueBoundArtifact{}, false, err
		}
		key := string(source.Kind) + "\x00" + source.ObjectID
		if !validSourceKind(source.Kind) || !validQueueObjectID(source.ObjectID) || source.Revision <= 0 || ordinal != len(out.Sources) || (lastSource != "" && key <= lastSource) {
			rows.Close()
			return FinalQueueBoundArtifact{}, false, errors.New("stored final queue source is invalid")
		}
		lastSource = key
		out.Sources = append(out.Sources, source)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return FinalQueueBoundArtifact{}, false, err
	}
	if err := rows.Close(); err != nil {
		return FinalQueueBoundArtifact{}, false, err
	}
	if err := validateLoadedFinalQueueArtifact(&out.FinalQueueArtifact); err != nil {
		return FinalQueueBoundArtifact{}, false, err
	}
	return out, true, nil
}

// validateLoadedFinalQueueArtifact recomputes canonical digests and state.
// Complexity: time O(r log r+s log s+b), Omega(r+s), tight Theta(r log r+s log s+b); auxiliary space O(r+s+b), Omega(r+s), tight Theta(r+s+b), where r/s/b are loaded child rows/bytes.
func validateLoadedFinalQueueArtifact(out *FinalQueueArtifact) error {
	state := out.State
	updated := canonicalPostgresTime(out.UpdatedAt)
	canonical, err := canonicalFinalQueueArtifact(*out)
	if err != nil {
		return err
	}
	if state != FinalQueueStatePrepared && state != FinalQueueStateBound {
		return errors.New("stored final queue state is invalid")
	}
	if state == FinalQueueStatePrepared && !updated.Equal(canonical.PreparedAt) {
		return errors.New("stored final queue update time is invalid")
	}
	if state == FinalQueueStateBound && (updated.Before(canonical.PreparedAt) || !updated.Before(canonical.ExpiresAt)) {
		return errors.New("stored final queue update time is invalid")
	}
	if canonical.sourceSetDigest != out.sourceSetDigest || canonical.recipientSetDigest != out.recipientSetDigest || canonical.provenanceDigest != out.provenanceDigest {
		return errors.New("stored final queue digest mismatch")
	}
	canonical.State = state
	canonical.UpdatedAt = updated
	*out = canonical
	return nil
}

// validateBoundFinalQueueArtifact checks binding/lifecycle relations after artifact, binding and queue are read in one SQL snapshot.
// Complexity: time O(1), Omega(1), tight Theta(1); auxiliary space O(1), Omega(1), tight Theta(1).
func validateBoundFinalQueueArtifact(artifact FinalQueueBoundArtifact) error {
	if artifact.State != FinalQueueStateBound || artifact.BoundAt.Before(artifact.PreparedAt) || !artifact.BoundAt.Before(artifact.ExpiresAt) || !artifact.UpdatedAt.Equal(artifact.BoundAt) {
		return errors.New("stored final queue binding is invalid")
	}
	return nil
}

// artifactMatchesQueue compares prepared intent to the validated observed queue.
// Complexity: time O(r+s+b), Omega(1), tight Theta(r+s+b) for equal canonical inputs; auxiliary space O(1), Omega(1), tight Theta(1), where r/s are queue recipients/sources and b is compared scalar/element bytes.
func artifactMatchesQueue(artifact FinalQueueArtifact, queue QueueRecord, arrival string) error {
	if queue.ArrivalFingerprint != arrival || artifact.EnvelopeSender != queue.EnvelopeSender || artifact.NullEnvelopeSender != (queue.EnvelopeSender == "<>") || artifact.recipientSetDigest != queue.RecipientSetDigest || artifact.sourceSetDigest != queue.SourceSetDigest {
		return errors.New("final queue artifact does not match observed queue")
	}
	if len(artifact.Recipients) != len(queue.Recipients) {
		return errors.New("final queue recipient set does not match observed queue")
	}
	for i := range queue.Recipients {
		if artifact.Recipients[i] != queue.Recipients[i] {
			return errors.New("final queue recipient set does not match observed queue")
		}
	}
	if len(artifact.Sources) != len(queue.Sources) {
		return errors.New("final queue source set does not match observed queue")
	}
	for i := range queue.Sources {
		if artifact.Sources[i].QueueSource != queue.Sources[i] {
			return errors.New("final queue source set does not match observed queue")
		}
	}
	return nil
}

// sameFinalQueueIntent compares immutable prepared intent, ignoring persistence
// timestamps/state supplied by the first successful prepare.
// Complexity: time O(r+s+b), Omega(1), tight Theta(r+s+b) for equal canonical inputs; auxiliary space O(1), Omega(1), tight Theta(1), using explicit scalar and slice comparisons without allocation.
func sameFinalQueueIntent(a, b FinalQueueArtifact) bool {
	a.State, b.State = "", ""
	a.PreparedAt, b.PreparedAt = time.Time{}, time.Time{}
	a.UpdatedAt, b.UpdatedAt = time.Time{}, time.Time{}
	if a.ArtifactID != b.ArtifactID || a.SignedMessageID != b.SignedMessageID || !a.SignedDate.Equal(b.SignedDate) || a.ContentSHA256 != b.ContentSHA256 || a.ContentBytes != b.ContentBytes || a.LocalIdentityID != b.LocalIdentityID || a.LocalMailboxID != b.LocalMailboxID || a.EnvelopeSender != b.EnvelopeSender || a.NullEnvelopeSender != b.NullEnvelopeSender || a.SignerIdentityID != b.SignerIdentityID || a.SignerFingerprint != b.SignerFingerprint || a.sourceSetDigest != b.sourceSetDigest || a.recipientSetDigest != b.recipientSetDigest || a.provenanceDigest != b.provenanceDigest || !a.ExpiresAt.Equal(b.ExpiresAt) || len(a.Recipients) != len(b.Recipients) || len(a.Sources) != len(b.Sources) {
		return false
	}
	for i := range a.Recipients {
		if a.Recipients[i] != b.Recipients[i] {
			return false
		}
	}
	for i := range a.Sources {
		if a.Sources[i] != b.Sources[i] {
			return false
		}
	}
	return true
}

// validGeneratedSignedMessageID admits the generated RFC5322 dot-atom form used by SignedForwardBuilder.
// Complexity: time O(n), Omega(1), tight Theta(n); auxiliary space O(1), Omega(1), tight Theta(1), where n is the bounded Message-ID length.
func validGeneratedSignedMessageID(value string) bool { return generatedmsgid.Valid(value) }

// validQueueBinding validates caller-independent queue binding identity.
// Complexity: time O(n), Omega(1), tight Theta(n); auxiliary space O(1), Omega(1), tight Theta(1).
func validQueueBinding(in FinalQueueBinding) bool {
	return validQueueInstanceID(in.ArtifactID) && validQueueInstanceID(in.InstanceID) && validLongQueueID(in.QueueID) && validLowerHexDigest(in.ArrivalFingerprint)
}

// validQueueInstanceID shares the queue object boundary for local opaque IDs.
// Complexity: time O(n), Omega(1), tight Theta(n); auxiliary space O(1),
// Omega(1), tight Theta(1).
func validQueueInstanceID(value string) bool { return validQueueObjectID(value) && len(value) <= 128 }

// digestFinalQueueProvenance hashes canonical immutable fields and source
// revisions. It excludes body bytes and any caller-supplied digest authority.
// Complexity: time O(s+b), Omega(s), tight Theta(s+b); auxiliary space O(1), Omega(1), tight Theta(1), where s is sources and b is framed scalar/source bytes; recipients are represented by an already-computed digest frame.
func digestFinalQueueProvenance(in FinalQueueArtifact) string {
	hash := sha256.New()
	writeFrame := func(value string) {
		var size [8]byte
		binary.BigEndian.PutUint64(size[:], uint64(len(value)))
		hash.Write(size[:])
		hash.Write([]byte(value))
	}
	writeFrame(in.ArtifactID)
	writeFrame(in.SignedMessageID)
	writeFrame(in.SignedDate.Format(time.RFC3339Nano))
	writeFrame(in.ExpiresAt.Format(time.RFC3339Nano))
	writeFrame(in.ContentSHA256)
	writeFrame(in.EnvelopeSender)
	writeFrame(in.LocalIdentityID)
	writeFrame(in.LocalMailboxID)
	writeFrame(in.SignerIdentityID)
	writeFrame(in.SignerFingerprint)
	writeFrame(in.recipientSetDigest)
	writeFrame(in.sourceSetDigest)
	var num [8]byte
	binary.BigEndian.PutUint64(num[:], uint64(in.ContentBytes))
	hash.Write(num[:])
	for _, source := range in.Sources {
		writeFrame(string(source.Kind))
		writeFrame(source.ObjectID)
		binary.BigEndian.PutUint64(num[:], uint64(source.Revision))
		hash.Write(num[:])
	}
	return hex.EncodeToString(hash.Sum(nil))
}
