package notifyruntime

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"forgejo/gotthboard/gotth-mail/internal/notification"
	"forgejo/gotthboard/gotth-mail/internal/ops"
)

type SQLNotificationEventStates struct{ DB *sql.DB }

func (s SQLNotificationEventStates) Observe(ctx context.Context, key, state string, alerting bool, now time.Time) (string, bool, error) {
	key = strings.TrimSpace(key)
	if s.DB == nil || key == "" || len(key) > 200 || state == "" {
		return "", false, errors.New("valid notification event state required")
	}
	stateSum := sha256.Sum256([]byte(state))
	stateHash := hex.EncodeToString(stateSum[:])
	keySum := sha256.Sum256([]byte(key))
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return "", false, err
	}
	defer tx.Rollback()
	var previousHash string
	var sequence int64
	var pending sql.NullString
	err = tx.QueryRowContext(ctx, `SELECT state_hash,sequence,pending_alert_id FROM notification_event_states WHERE event_key=$1 FOR UPDATE`, key).Scan(&previousHash, &sequence, &pending)
	if errors.Is(err, sql.ErrNoRows) {
		sequence = 1
		alertID := ""
		if alerting {
			alertID = fmt.Sprintf("event-%s-%d", hex.EncodeToString(keySum[:12]), sequence)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO notification_event_states(event_key,state_hash,sequence,pending_alert_id,updated_at) VALUES ($1,$2,$3,$4,$5)`, key, stateHash, sequence, nullString(alertID), now.UTC()); err != nil {
			return "", false, err
		}
		if err := tx.Commit(); err != nil {
			return "", false, err
		}
		return alertID, alertID != "", nil
	}
	if err != nil {
		return "", false, err
	}
	if previousHash == stateHash {
		if err := tx.Commit(); err != nil {
			return "", false, err
		}
		return pending.String, pending.Valid, nil
	}
	sequence++
	alertID := ""
	if alerting {
		alertID = fmt.Sprintf("event-%s-%d", hex.EncodeToString(keySum[:12]), sequence)
	}
	if _, err := tx.ExecContext(ctx, `UPDATE notification_event_states SET state_hash=$2,sequence=$3,pending_alert_id=$4,updated_at=$5 WHERE event_key=$1`, key, stateHash, sequence, nullString(alertID), now.UTC()); err != nil {
		return "", false, err
	}
	if err := tx.Commit(); err != nil {
		return "", false, err
	}
	return alertID, alertID != "", nil
}

func (s SQLNotificationEventStates) Acknowledge(ctx context.Context, key, alertID string, now time.Time) error {
	res, err := s.DB.ExecContext(ctx, `UPDATE notification_event_states SET pending_alert_id=NULL,updated_at=$3 WHERE event_key=$1 AND pending_alert_id=$2`, key, alertID, now.UTC())
	if err != nil {
		return err
	}
	if n, err := res.RowsAffected(); err != nil || n != 1 {
		return errors.New("notification event acknowledgement rejected")
	}
	return nil
}

type OperationalMonitor struct {
	Service  *notification.Service
	States   SQLNotificationEventStates
	Doctor   func(context.Context) (ops.DoctorReport, error)
	Queue    QueueController
	Backup   func(context.Context) (ops.Backup, bool, error)
	Snapshot func(context.Context) (ops.SnapshotView, bool, error)
	Abuse    func(context.Context) (int, error)
	Now      func() time.Time
}

func (m OperationalMonitor) RunOnce(ctx context.Context) error {
	if m.Service == nil || m.States.DB == nil {
		return errors.New("operational notification monitor dependencies required")
	}
	var failures []error
	if m.Doctor != nil {
		report, err := m.Doctor(ctx)
		if err != nil {
			failures = append(failures, err)
		} else {
			checks := append([]ops.Check(nil), report.Checks...)
			sort.Slice(checks, func(i, j int) bool {
				return checks[i].Category+"\x00"+checks[i].Name < checks[j].Category+"\x00"+checks[j].Name
			})
			for _, check := range checks {
				class := "doctor.failure"
				if check.Category == "TLS" {
					class = "certificate.renewal.failure"
				} else if check.Category == "plugin" {
					class = "plugin.health.failure"
				}
				alert := notification.Alert{Class: class, Severity: notification.SeverityCritical, Title: "Operational check failed", Summary: check.Category + " " + check.Name + " failed", Resource: notification.ResourceRef{Type: "doctor_check", ID: check.Name}}
				if err := m.observe(ctx, "doctor:"+check.Category+":"+check.Name, string(check.Status), check.Status == ops.Fail, alert); err != nil {
					failures = append(failures, err)
				}
			}
		}
	}
	if m.Queue != nil {
		queue, err := m.Queue.Snapshot(ctx, "")
		if err != nil {
			failures = append(failures, err)
		} else {
			state := "clear"
			if queue.Deferred > 0 {
				state = "deferred"
			}
			alert := notification.Alert{Class: "queue.deferred", Severity: notification.SeverityWarning, Title: "Deferred mail detected", Summary: fmt.Sprintf("deferred=%d total=%d", queue.Deferred, queue.Total), Resource: notification.ResourceRef{Type: "postfix_queue", ID: "default"}}
			if err := m.observe(ctx, "queue:default", state, queue.Deferred > 0, alert); err != nil {
				failures = append(failures, err)
			}
		}
	}
	if m.Backup != nil {
		backup, ok, err := m.Backup(ctx)
		if err != nil {
			failures = append(failures, err)
		} else if ok {
			alert := notification.Alert{Class: "backup.verification.failure", Severity: notification.SeverityCritical, Title: "Backup verification failed", Summary: "latest backup verification failed", Resource: notification.ResourceRef{Type: "backup", ID: backup.ArtifactRef}}
			if err := m.observe(ctx, "backup:latest", backup.ArtifactRef+":"+backup.Status, backup.Status == "failed", alert); err != nil {
				failures = append(failures, err)
			}
		}
	}
	if m.Snapshot != nil {
		snapshot, ok, err := m.Snapshot(ctx)
		if err != nil {
			failures = append(failures, err)
		} else if ok {
			alert := notification.Alert{Class: "deployment.status.changed", Severity: notification.SeverityInfo, Title: "Deployment state recorded", Summary: "A new deployment snapshot is active", Resource: notification.ResourceRef{Type: "snapshot", ID: snapshot.ID}}
			if err := m.observe(ctx, "deployment:current", snapshot.ID, true, alert); err != nil {
				failures = append(failures, err)
			}
		}
	}
	if m.Abuse != nil {
		count, err := m.Abuse(ctx)
		if err != nil {
			failures = append(failures, err)
		} else {
			state := "clear"
			if count > 0 {
				state = "active"
			}
			alert := notification.Alert{Class: "abuse.rate_limit", Severity: notification.SeverityWarning, Title: "Abuse signal detected", Summary: fmt.Sprintf("active_signals=%d", count), Resource: notification.ResourceRef{Type: "abuse_summary", ID: "current"}}
			if err := m.observe(ctx, "abuse:current", state, count > 0, alert); err != nil {
				failures = append(failures, err)
			}
		}
	}
	return errors.Join(failures...)
}

func (m OperationalMonitor) observe(ctx context.Context, key, state string, alerting bool, alert notification.Alert) error {
	now := m.now()
	id, pending, err := m.States.Observe(ctx, key, state, alerting, now)
	if err != nil || !pending {
		return err
	}
	alert.ID = id
	alert.CorrelationID = id
	record, sendErr := m.Service.SendAlert(ctx, alert)
	if record.Status == notification.StatusDelivered || record.Status == notification.StatusFailedPermanent {
		if err := m.States.Acknowledge(ctx, key, id, m.now()); err != nil {
			return err
		}
	}
	return sendErr
}

func (m OperationalMonitor) Start(ctx context.Context, interval time.Duration, report func(error)) {
	if interval <= 0 {
		interval = time.Minute
	}
	run := func() {
		if err := m.RunOnce(ctx); err != nil && report != nil {
			report(err)
		}
	}
	run()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			run()
		}
	}
}

func (m OperationalMonitor) now() time.Time {
	if m.Now != nil {
		return m.Now().UTC()
	}
	return time.Now().UTC()
}

func nullString(value string) any {
	if value == "" {
		return nil
	}
	return value
}
