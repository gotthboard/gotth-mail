package outboundpolicy

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"database/sql/driver"
	"encoding/binary"
	"encoding/json"
	"errors"
	"time"

	"forgejo/gotthboard/gotth-mail/internal/audit"
)

type QueueMetadata struct {
	QueueID            string   `json:"queue_id"`
	ArrivalFingerprint string   `json:"arrival_fingerprint"`
	EnvelopeSender     string   `json:"envelope_sender"`
	Recipients         []string `json:"recipients"`
	Held               bool     `json:"held"`
}

type QueueInspector interface {
	Inspect(context.Context, string) (QueueMetadata, error)
}

type QueueHolder interface {
	Hold(context.Context, string) error
}

type ReconcileResult struct {
	Record  QueueRecord `json:"record"`
	Changed bool        `json:"changed"`
}

type QueueReconciler struct {
	Store     QueueStore
	Inspector QueueInspector
	Holder    QueueHolder
}

// RequireHold records the current policy revisions before any privileged
// queue operation. Repeated identical requirements preserve the current
// reconciliation state.
// Complexity: time O(n*m), Omega(n), tight Theta(n*m); auxiliary space O(n*m),
// Omega(n), where bounded n is revisions and m is maximum domain length; one
// serializable row transaction and one audit insert are additive.
func (s QueueStore) RequireHold(ctx context.Context, actor audit.ActorRef, correlationID, queueID string, decision Decision) error {
	if s.DB == nil {
		return errors.New("outbound queue database is unavailable")
	}
	if actor.Type == "" || actor.ID == "" || correlationID == "" {
		return errors.New("actor and correlation ID are required")
	}
	if !validLongQueueID(queueID) || decision.Action != ActionDefer || decision.Reason != ReasonPolicyHold {
		return errors.New("invalid outbound queue hold decision")
	}
	revisions, encoded, err := canonicalPolicyRevisions(decision.Revisions)
	if err != nil {
		return err
	}
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var state HoldState
	var priorReason sql.NullString
	var priorEncoded []byte
	if err := tx.QueryRowContext(ctx, `SELECT hold_state,policy_reason,policy_revisions_json FROM outbound_queue_messages WHERE queue_id=$1 FOR UPDATE`, queueID).Scan(&state, &priorReason, &priorEncoded); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return errors.New("outbound queue record not found")
		}
		return err
	}
	if !validHoldState(state) {
		return errors.New("stored outbound queue state is invalid")
	}
	var prior map[string]uint64
	if err := json.Unmarshal(priorEncoded, &prior); err != nil {
		return errors.New("stored outbound queue policy revisions are invalid")
	}
	if len(prior) > 0 {
		canonicalPrior, _, canonicalErr := canonicalPolicyRevisions(prior)
		if canonicalErr != nil || !revisionMapsEqual(prior, canonicalPrior) {
			return errors.New("stored outbound queue policy revisions are invalid")
		}
	}
	priorValue := Reason("")
	if priorReason.Valid {
		priorValue = Reason(priorReason.String)
	}
	if !validQueuePolicyState(state, priorReason.Valid, priorValue, prior) {
		return errors.New("stored outbound queue policy state is invalid")
	}
	if priorReason.Valid && Reason(priorReason.String) == decision.Reason && revisionMapsEqual(prior, revisions) && (state == HoldRequired || state == HoldReconciling || state == HoldApplied || state == HoldReconciliationError) {
		return nil
	}
	now := s.now()
	if _, err := tx.ExecContext(ctx, `UPDATE outbound_queue_messages SET hold_state='hold_required',policy_reason=$1,policy_revisions_json=$2,last_error_code=NULL,updated_at=$3 WHERE queue_id=$4`, string(decision.Reason), encoded, now, queueID); err != nil {
		return err
	}
	if err := audit.WriteSQL(ctx, tx, audit.Event{
		Time:   now,
		Actor:  actor,
		Action: "queue.policy_hold.required",
		Resource: audit.ResourceRef{
			Type: "postfix_queue", ID: queueID,
		},
		BeforeRedacted: map[string]any{"state": state},
		AfterRedacted:  map[string]any{"state": HoldRequired, "reason": decision.Reason, "revisions": revisions},
		CorrelationID:  correlationID,
		Result:         "success",
	}); err != nil {
		return err
	}
	return tx.Commit()
}

// Reconcile verifies current queue metadata on both sides of one narrow hold
// operation. A PostgreSQL session lock serializes helpers for the same queue;
// every state transition is committed and audited separately from the
// irreversible external boundary.
// Complexity: time O(r log r+s log s+b), Omega(r+s), tight
// Theta(r log r+s log s+b); auxiliary space O(r+s+b), Omega(r+s), where r,
// s, and b use QueueStore bounds; inspector/helper latency is additive.
func (r QueueReconciler) Reconcile(ctx context.Context, actor audit.ActorRef, correlationID, queueID string) (result ReconcileResult, err error) {
	if r.Store.DB == nil || r.Inspector == nil || r.Holder == nil {
		return ReconcileResult{}, errors.New("outbound queue reconciler is unavailable")
	}
	if actor.Type == "" || actor.ID == "" || correlationID == "" || !validLongQueueID(queueID) {
		return ReconcileResult{}, errors.New("invalid outbound queue reconciliation request")
	}
	conn, err := r.Store.DB.Conn(ctx)
	if err != nil {
		return ReconcileResult{}, err
	}
	lockKey := queueAdvisoryLockKey(queueID)
	if _, err = conn.ExecContext(ctx, `SELECT pg_advisory_lock($1)`, lockKey); err != nil {
		conn.Close()
		return ReconcileResult{}, err
	}
	defer func() {
		unlockCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, unlockErr := conn.ExecContext(unlockCtx, `SELECT pg_advisory_unlock($1)`, lockKey)
		if unlockErr != nil {
			_ = conn.Raw(func(any) error { return driver.ErrBadConn })
			if err == nil {
				err = unlockErr
			}
		}
		if closeErr := conn.Close(); err == nil && closeErr != nil {
			err = closeErr
		}
	}()
	record, err := loadQueueRecord(ctx, conn, queueID)
	if err != nil {
		return ReconcileResult{}, err
	}
	if record.HoldState == HoldApplied {
		metadata, inspectErr := r.Inspector.Inspect(ctx, queueID)
		if inspectErr == nil && metadata.Held && matchesQueueMetadata(record, metadata) {
			return ReconcileResult{Record: record, Changed: false}, nil
		}
	}
	if record.HoldState != HoldRequired && record.HoldState != HoldReconciliationError && record.HoldState != HoldReconciling && record.HoldState != HoldApplied {
		return ReconcileResult{}, errors.New("outbound queue message does not require a hold")
	}
	if err := startQueueReconciliation(ctx, conn, r.Store, actor, correlationID, record); err != nil {
		return ReconcileResult{}, err
	}
	metadata, inspectErr := r.Inspector.Inspect(ctx, queueID)
	if inspectErr != nil {
		return r.fail(ctx, conn, actor, correlationID, record, "queue_inspection_failed")
	}
	if !matchesQueueMetadata(record, metadata) {
		return r.fail(ctx, conn, actor, correlationID, record, "queue_metadata_mismatch")
	}
	if !metadata.Held {
		if holdErr := r.Holder.Hold(ctx, queueID); holdErr != nil {
			return r.fail(ctx, conn, actor, correlationID, record, "queue_hold_failed")
		}
		metadata, inspectErr = r.Inspector.Inspect(ctx, queueID)
		if inspectErr != nil {
			return r.fail(ctx, conn, actor, correlationID, record, "queue_post_hold_inspection_failed")
		}
		if !matchesQueueMetadata(record, metadata) {
			return r.fail(ctx, conn, actor, correlationID, record, "queue_post_hold_metadata_mismatch")
		}
	}
	if !metadata.Held {
		return r.fail(ctx, conn, actor, correlationID, record, "queue_hold_not_observed")
	}
	if err := finishQueueReconciliation(ctx, conn, r.Store, actor, correlationID, record, HoldApplied, ""); err != nil {
		return ReconcileResult{}, err
	}
	stored, err := loadQueueRecord(ctx, conn, queueID)
	if err != nil {
		return ReconcileResult{}, err
	}
	return ReconcileResult{Record: stored, Changed: true}, nil
}

// fail records one retryable machine-readable reconciliation error.
// Complexity: time O(1), Omega(1), tight Theta(1); auxiliary space O(1),
// Omega(1), tight Theta(1), plus one serializable update/audit transaction.
func (r QueueReconciler) fail(ctx context.Context, conn *sql.Conn, actor audit.ActorRef, correlationID string, record QueueRecord, code string) (ReconcileResult, error) {
	if err := finishQueueReconciliation(ctx, conn, r.Store, actor, correlationID, record, HoldReconciliationError, code); err != nil {
		return ReconcileResult{}, err
	}
	stored, err := loadQueueRecord(ctx, conn, record.QueueID)
	if err != nil {
		return ReconcileResult{}, err
	}
	return ReconcileResult{Record: stored, Changed: true}, errors.New(code)
}

// startQueueReconciliation commits the attempt counter and audit before the
// external helper can run.
// Complexity: time O(1), Omega(1), tight Theta(1); auxiliary space O(1),
// Omega(1), tight Theta(1).
func startQueueReconciliation(ctx context.Context, conn *sql.Conn, store QueueStore, actor audit.ActorRef, correlationID string, record QueueRecord) error {
	tx, err := conn.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return err
	}
	defer tx.Rollback()
	now := store.now()
	result, err := tx.ExecContext(ctx, `UPDATE outbound_queue_messages SET hold_state='reconciling',reconciliation_attempts=reconciliation_attempts+1,last_error_code=NULL,updated_at=$1 WHERE queue_id=$2 AND hold_state IN ('hold_required','reconciliation_error','reconciling','held')`, now, record.QueueID)
	if err != nil {
		return err
	}
	affected, err := result.RowsAffected()
	if err != nil || affected != 1 {
		if err != nil {
			return err
		}
		return errors.New("outbound queue reconciliation state changed")
	}
	if err := audit.WriteSQL(ctx, tx, audit.Event{
		Time:   now,
		Actor:  actor,
		Action: "queue.policy_hold.reconcile_start",
		Resource: audit.ResourceRef{
			Type: "postfix_queue", ID: record.QueueID,
		},
		BeforeRedacted: map[string]any{"state": record.HoldState, "attempts": record.ReconciliationAttempts},
		AfterRedacted:  map[string]any{"state": HoldReconciling, "attempts": record.ReconciliationAttempts + 1},
		CorrelationID:  correlationID,
		Result:         "success",
	}); err != nil {
		return err
	}
	return tx.Commit()
}

// finishQueueReconciliation commits either verified hold success or one
// retryable failure code. It never stores helper output.
// Complexity: time O(1), Omega(1), tight Theta(1); auxiliary space O(1),
// Omega(1), tight Theta(1).
func finishQueueReconciliation(ctx context.Context, conn *sql.Conn, store QueueStore, actor audit.ActorRef, correlationID string, record QueueRecord, state HoldState, code string) error {
	if state != HoldApplied && state != HoldReconciliationError {
		return errors.New("invalid outbound queue reconciliation result")
	}
	if state == HoldReconciliationError && !validQueueErrorCode(code) {
		return errors.New("invalid outbound queue reconciliation error code")
	}
	tx, err := conn.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return err
	}
	defer tx.Rollback()
	now := store.now()
	var errorCode any
	if code != "" {
		errorCode = code
	}
	result, err := tx.ExecContext(ctx, `UPDATE outbound_queue_messages SET hold_state=$1,last_error_code=$2,updated_at=$3 WHERE queue_id=$4 AND hold_state='reconciling'`, string(state), errorCode, now, record.QueueID)
	if err != nil {
		return err
	}
	affected, err := result.RowsAffected()
	if err != nil || affected != 1 {
		if err != nil {
			return err
		}
		return errors.New("outbound queue reconciliation state changed")
	}
	action := "queue.policy_hold.applied"
	resultName := "success"
	if state == HoldReconciliationError {
		action = "queue.policy_hold.failed"
		resultName = "failure"
	}
	if err := audit.WriteSQL(ctx, tx, audit.Event{
		Time:   now,
		Actor:  actor,
		Action: action,
		Resource: audit.ResourceRef{
			Type: "postfix_queue", ID: record.QueueID,
		},
		BeforeRedacted: map[string]any{"state": HoldReconciling},
		AfterRedacted:  map[string]any{"state": state, "error_code": errorCode},
		CorrelationID:  correlationID,
		Result:         resultName,
	}); err != nil {
		return err
	}
	return tx.Commit()
}

// matchesQueueMetadata canonicalizes the inspected sender and recipient set
// and compares the immutable arrival identity.
// Complexity: time O(r log r+b), Omega(r), tight Theta(r log r+b); auxiliary
// space O(r+b), Omega(r), where r is bounded recipients and b their bytes.
func matchesQueueMetadata(record QueueRecord, metadata QueueMetadata) bool {
	candidate, err := normalizeQueueRegistration(QueueRegistration{
		QueueID:            metadata.QueueID,
		ArrivalFingerprint: metadata.ArrivalFingerprint,
		EnvelopeSender:     metadata.EnvelopeSender,
		Recipients:         metadata.Recipients,
		Sources:            record.Sources,
	})
	return err == nil && sameQueueIdentity(record, candidate)
}

// canonicalPolicyRevisions normalizes, bounds, and deterministically encodes
// the policy revisions that caused a hold.
// Complexity: time O(n*m), Omega(n), tight Theta(n*m); auxiliary space O(n*m),
// Omega(n), where n is at most maxGoverningDomains and m is domain length.
func canonicalPolicyRevisions(revisions map[string]uint64) (map[string]uint64, []byte, error) {
	if len(revisions) == 0 || len(revisions) > maxGoverningDomains {
		return nil, nil, errors.New("invalid outbound queue policy revisions")
	}
	canonical := make(map[string]uint64, len(revisions))
	for rawDomain, revision := range revisions {
		domain, err := NormalizeDomain(rawDomain)
		if err != nil || revision == 0 {
			return nil, nil, errors.New("invalid outbound queue policy revisions")
		}
		if prior, exists := canonical[domain]; exists && prior != revision {
			return nil, nil, errors.New("conflicting outbound queue policy revisions")
		}
		canonical[domain] = revision
	}
	encoded, err := json.Marshal(canonical)
	if err != nil {
		return nil, nil, err
	}
	return canonical, encoded, nil
}

// revisionMapsEqual compares two bounded domain/revision maps.
// Complexity: time O(n), Omega(1), tight Theta(n); auxiliary space O(1),
// Omega(1), tight Theta(1), where n is the first map's entries.
func revisionMapsEqual(left, right map[string]uint64) bool {
	if len(left) != len(right) {
		return false
	}
	for domain, revision := range left {
		if right[domain] != revision {
			return false
		}
	}
	return true
}

// queueAdvisoryLockKey maps one validated queue ID to a stable signed 64-bit
// PostgreSQL advisory-lock key.
// Complexity: time O(n), Omega(n), tight Theta(n); auxiliary space O(1),
// Omega(1), tight Theta(1), where n is the bounded queue-ID length.
func queueAdvisoryLockKey(queueID string) int64 {
	digest := sha256.Sum256([]byte(queueID))
	return int64(binary.BigEndian.Uint64(digest[:8]))
}
