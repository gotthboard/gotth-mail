package outboundpolicy

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"sort"
	"strconv"
	"time"

	"forgejo/gotthboard/gotth-mail/internal/audit"
)

type QueueReleaseBoundary interface {
	QueueInspector
	Release(context.Context, string) error
}

type QueueReleasePlan struct {
	QueueID          string            `json:"queue_id"`
	HoldState        HoldState         `json:"hold_state"`
	PolicyRevisions  map[string]uint64 `json:"policy_revisions"`
	ConfirmationHash string            `json:"confirmation_hash"`
}

type QueueReleaseResult struct {
	Record  QueueRecord `json:"record"`
	Changed bool        `json:"changed"`
}

type QueueDiagnostic struct {
	QueueID                string            `json:"queue_id"`
	HoldState              HoldState         `json:"hold_state"`
	PolicyReason           Reason            `json:"policy_reason,omitempty"`
	PolicyRevisions        map[string]uint64 `json:"policy_revisions,omitempty"`
	ReconciliationAttempts uint64            `json:"reconciliation_attempts"`
	LastErrorCode          string            `json:"last_error_code,omitempty"`
	RecipientCount         int               `json:"recipient_count"`
	SourceCount            int               `json:"source_count"`
	PostfixHeld            bool              `json:"postfix_held"`
	Consistent             bool              `json:"consistent"`
}

type QueueReleaseService struct {
	Store    QueueStore
	Boundary QueueReleaseBoundary
}

// Diagnose compares redacted durable queue state with one live Postfix
// observation without returning envelope addresses or source identifiers.
// Complexity: time O(r log r+s log s+b), Omega(r+s); auxiliary space
// O(r+s+b), with QueueStore bounds; one helper round trip is additive.
func (s QueueReleaseService) Diagnose(ctx context.Context, queueID string) (QueueDiagnostic, error) {
	if s.Store.DB == nil || s.Boundary == nil || !validLongQueueID(queueID) {
		return QueueDiagnostic{}, errors.New("invalid outbound queue diagnostic request")
	}
	record, err := s.Store.Load(ctx, queueID)
	if err != nil {
		return QueueDiagnostic{}, err
	}
	diagnostic := QueueDiagnostic{
		QueueID:                record.QueueID,
		HoldState:              record.HoldState,
		PolicyReason:           record.PolicyReason,
		PolicyRevisions:        record.PolicyRevisions,
		ReconciliationAttempts: record.ReconciliationAttempts,
		LastErrorCode:          record.LastErrorCode,
		RecipientCount:         len(record.Recipients),
		SourceCount:            len(record.Sources),
	}
	metadata, err := s.Boundary.Inspect(ctx, queueID)
	if err != nil {
		return diagnostic, errors.New("Postfix queue diagnostic unavailable")
	}
	diagnostic.PostfixHeld = metadata.Held
	diagnostic.Consistent = matchesQueueMetadata(record, metadata)
	if record.HoldState == HoldApplied {
		diagnostic.Consistent = diagnostic.Consistent && metadata.Held
	}
	if record.HoldState == HoldReleased {
		diagnostic.Consistent = diagnostic.Consistent && !metadata.Held
	}
	if !diagnostic.Consistent {
		return diagnostic, errors.New("Postfix queue diagnostic mismatch")
	}
	return diagnostic, nil
}

// Preview proves that every remaining recipient is currently permitted and
// returns a confirmation bound to immutable queue identity and policy state.
// Complexity: time O(r*s*m+s log s+b), Omega(r+s); auxiliary space O(s*m+b),
// where r is bounded recipients, s sources, m domain length, and b identity
// bytes; indexed policy queries are additive.
func (s QueueReleaseService) Preview(ctx context.Context, queueID string) (QueueReleasePlan, error) {
	if s.Store.DB == nil || !validLongQueueID(queueID) {
		return QueueReleasePlan{}, errors.New("invalid outbound queue release preview")
	}
	record, err := s.Store.Load(ctx, queueID)
	if err != nil {
		return QueueReleasePlan{}, err
	}
	return s.previewRecord(ctx, record)
}

// Release serializes one confirmed release, rechecks current policy under the
// queue lock, verifies live metadata on both sides of `postsuper -H`, and
// audits every externally visible state transition.
// Complexity: time O(r*s*m+r log r+s log s+b), Omega(r+s); auxiliary space
// O(r+s*m+b), with Preview variables; helper latency is additive.
func (s QueueReleaseService) Release(ctx context.Context, actor audit.ActorRef, correlationID, queueID, confirmation string) (result QueueReleaseResult, err error) {
	if s.Store.DB == nil || s.Boundary == nil || actor.Type == "" || actor.ID == "" || correlationID == "" || !validLongQueueID(queueID) || !validLowerHexDigest(confirmation) {
		return QueueReleaseResult{}, errors.New("invalid outbound queue release request")
	}
	conn, err := s.Store.DB.Conn(ctx)
	if err != nil {
		return QueueReleaseResult{}, err
	}
	lockKey := queueAdvisoryLockKey(queueID)
	if _, err = conn.ExecContext(ctx, `SELECT pg_advisory_lock($1)`, lockKey); err != nil {
		conn.Close()
		return QueueReleaseResult{}, err
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
		return QueueReleaseResult{}, err
	}
	plan, err := s.previewRecord(ctx, record)
	if err != nil {
		return QueueReleaseResult{}, err
	}
	if plan.ConfirmationHash != confirmation {
		return QueueReleaseResult{}, errors.New("outbound queue release confirmation is stale")
	}
	metadata, inspectErr := s.Boundary.Inspect(ctx, queueID)
	if record.HoldState == HoldReleased {
		if inspectErr == nil && !metadata.Held && matchesQueueMetadata(record, metadata) {
			return QueueReleaseResult{Record: record, Changed: false}, nil
		}
		return QueueReleaseResult{}, errors.New("released outbound queue metadata is inconsistent")
	}
	if record.HoldState != HoldApplied && record.HoldState != HoldReleaseError && record.HoldState != HoldReleaseReconciling {
		return QueueReleaseResult{}, errors.New("outbound queue message is not releasable")
	}
	if inspectErr != nil || !metadata.Held || !matchesQueueMetadata(record, metadata) {
		return QueueReleaseResult{}, errors.New("held outbound queue metadata is unavailable")
	}
	if err := startQueueRelease(ctx, conn, s.Store, actor, correlationID, record); err != nil {
		return QueueReleaseResult{}, err
	}
	if releaseErr := s.Boundary.Release(ctx, queueID); releaseErr != nil {
		return s.fail(ctx, conn, actor, correlationID, record, "queue_release_failed")
	}
	metadata, inspectErr = s.Boundary.Inspect(ctx, queueID)
	if inspectErr != nil {
		return s.fail(ctx, conn, actor, correlationID, record, "queue_post_release_inspection_failed")
	}
	if metadata.Held || !matchesQueueMetadata(record, metadata) {
		return s.fail(ctx, conn, actor, correlationID, record, "queue_release_not_verified")
	}
	if err := finishQueueRelease(ctx, conn, s.Store, actor, correlationID, record, HoldReleased, ""); err != nil {
		return QueueReleaseResult{}, err
	}
	stored, err := loadQueueRecord(ctx, conn, queueID)
	if err != nil {
		return QueueReleaseResult{}, err
	}
	return QueueReleaseResult{Record: stored, Changed: true}, nil
}

// previewRecord validates the releasable state and evaluates all recipients
// against one current authoritative governing snapshot.
// Complexity: time O(r*s*m+s log s+b), Omega(r+s); auxiliary space O(s*m+b),
// with Preview variables.
func (s QueueReleaseService) previewRecord(ctx context.Context, record QueueRecord) (QueueReleasePlan, error) {
	if record.HoldState != HoldApplied && record.HoldState != HoldReleaseError && record.HoldState != HoldReleaseReconciling && record.HoldState != HoldReleased {
		return QueueReleasePlan{}, errors.New("outbound queue message is not releasable")
	}
	governing, err := resolvePolicySources(ctx, s.Store.DB, record.Sources)
	if err != nil {
		return QueueReleasePlan{}, err
	}
	for _, recipient := range record.Recipients {
		decision := Evaluate(Request{Stage: StageTransport, QueueID: record.QueueID, Recipient: recipient, Governing: governing})
		if decision.Action != ActionOK {
			return QueueReleasePlan{}, errors.New("outbound queue remains forbidden by current policy")
		}
	}
	revisions, snapshot, err := releasePolicySnapshot(governing)
	if err != nil {
		return QueueReleasePlan{}, err
	}
	values := []string{"gotth-mail/queue-release/v1", record.QueueID, record.ArrivalFingerprint, record.RecipientSetDigest, record.SourceSetDigest}
	values = append(values, snapshot...)
	return QueueReleasePlan{QueueID: record.QueueID, HoldState: record.HoldState, PolicyRevisions: revisions, ConfirmationHash: digestStrings(values)}, nil
}

// releasePolicySnapshot canonicalizes all current governing states, including
// unrestricted revisions, for stale-confirmation protection.
// Complexity: time O(s log s+s*m), Omega(s); auxiliary space O(s*m).
func releasePolicySnapshot(governing []GoverningDomain) (map[string]uint64, []string, error) {
	type state struct {
		scope    Scope
		revision uint64
	}
	states := make(map[string]state, len(governing))
	for _, item := range governing {
		domain, err := NormalizeDomain(item.Domain)
		if err != nil || domain != item.Domain || !validScope(item.Scope) || item.Revision == 0 {
			return nil, nil, errors.New("invalid outbound release policy snapshot")
		}
		candidate := state{scope: item.Scope, revision: item.Revision}
		if prior, exists := states[domain]; exists && prior != candidate {
			return nil, nil, errors.New("conflicting outbound release policy snapshot")
		}
		states[domain] = candidate
	}
	if len(states) == 0 {
		return nil, nil, errors.New("empty outbound release policy snapshot")
	}
	domains := make([]string, 0, len(states))
	for domain := range states {
		domains = append(domains, domain)
	}
	sort.Strings(domains)
	revisions := make(map[string]uint64, len(domains))
	snapshot := make([]string, 0, len(domains))
	for _, domain := range domains {
		item := states[domain]
		revisions[domain] = item.revision
		snapshot = append(snapshot, domain+"\x00"+string(item.scope)+"\x00"+strconv.FormatUint(item.revision, 10))
	}
	return revisions, snapshot, nil
}

// fail records one retryable release error after a committed release attempt.
// Complexity: time and auxiliary space O(1), plus one transaction and reload.
func (s QueueReleaseService) fail(ctx context.Context, conn *sql.Conn, actor audit.ActorRef, correlationID string, record QueueRecord, code string) (QueueReleaseResult, error) {
	if err := finishQueueRelease(ctx, conn, s.Store, actor, correlationID, record, HoldReleaseError, code); err != nil {
		return QueueReleaseResult{}, err
	}
	stored, err := loadQueueRecord(ctx, conn, record.QueueID)
	if err != nil {
		return QueueReleaseResult{}, err
	}
	return QueueReleaseResult{Record: stored, Changed: true}, errors.New(code)
}

// startQueueRelease commits release intent and audit before the helper runs.
// Complexity: time and auxiliary space O(1), plus one serializable transaction.
func startQueueRelease(ctx context.Context, conn *sql.Conn, store QueueStore, actor audit.ActorRef, correlationID string, record QueueRecord) error {
	tx, err := conn.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return err
	}
	defer tx.Rollback()
	now := store.now()
	result, err := tx.ExecContext(ctx, `UPDATE outbound_queue_messages SET hold_state='release_reconciling',reconciliation_attempts=reconciliation_attempts+1,last_error_code=NULL,updated_at=$1 WHERE queue_id=$2 AND hold_state IN ('held','release_error','release_reconciling')`, now, record.QueueID)
	if err != nil {
		return err
	}
	affected, err := result.RowsAffected()
	if err != nil || affected != 1 {
		if err != nil {
			return err
		}
		return errors.New("outbound queue release state changed")
	}
	if err := audit.WriteSQL(ctx, tx, audit.Event{
		Time: now, Actor: actor, Action: "queue.policy_hold.release_start",
		Resource:       audit.ResourceRef{Type: "postfix_queue", ID: record.QueueID},
		BeforeRedacted: map[string]any{"state": record.HoldState, "attempts": record.ReconciliationAttempts},
		AfterRedacted:  map[string]any{"state": HoldReleaseReconciling, "attempts": record.ReconciliationAttempts + 1},
		CorrelationID:  correlationID, Result: "success",
	}); err != nil {
		return err
	}
	return tx.Commit()
}

// finishQueueRelease records either a verified release or one bounded retry
// error without storing helper output.
// Complexity: time and auxiliary space O(1), plus one serializable transaction.
func finishQueueRelease(ctx context.Context, conn *sql.Conn, store QueueStore, actor audit.ActorRef, correlationID string, record QueueRecord, state HoldState, code string) error {
	if state != HoldReleased && state != HoldReleaseError {
		return errors.New("invalid outbound queue release result")
	}
	if state == HoldReleaseError && !validQueueErrorCode(code) {
		return errors.New("invalid outbound queue release error code")
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
	result, err := tx.ExecContext(ctx, `UPDATE outbound_queue_messages SET hold_state=$1,last_error_code=$2,updated_at=$3 WHERE queue_id=$4 AND hold_state='release_reconciling'`, string(state), errorCode, now, record.QueueID)
	if err != nil {
		return err
	}
	affected, err := result.RowsAffected()
	if err != nil || affected != 1 {
		if err != nil {
			return err
		}
		return errors.New("outbound queue release state changed")
	}
	action, resultName := "queue.policy_hold.released", "success"
	if state == HoldReleaseError {
		action, resultName = "queue.policy_hold.release_failed", "failure"
	}
	if err := audit.WriteSQL(ctx, tx, audit.Event{
		Time: now, Actor: actor, Action: action,
		Resource:       audit.ResourceRef{Type: "postfix_queue", ID: record.QueueID},
		BeforeRedacted: map[string]any{"state": HoldReleaseReconciling},
		AfterRedacted:  map[string]any{"state": state, "error_code": errorCode},
		CorrelationID:  correlationID, Result: resultName,
	}); err != nil {
		return err
	}
	return tx.Commit()
}
