package notification

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"
)

type SQLRecorder struct{ DB *sql.DB }

func (s SQLRecorder) RecordPending(ctx context.Context, a Alert, now time.Time) error {
	if s.DB == nil {
		return errors.New("notification delivery db required")
	}
	clean, err := SanitizeAlert(a)
	if err != nil {
		return err
	}
	payload, err := json.Marshal(clean)
	if err != nil {
		return err
	}
	_, err = s.DB.ExecContext(ctx, `INSERT INTO notification_deliveries(alert_id, alert_json, status, reason, evidence_json, created_at, updated_at) VALUES ($1,$2,$3,'','{}',$4,$4) ON CONFLICT (alert_id) DO UPDATE SET alert_json=EXCLUDED.alert_json, status=EXCLUDED.status, reason='', evidence_json='{}', updated_at=EXCLUDED.updated_at`, clean.ID, string(payload), StatusPending, now.UTC())
	return err
}

func (s SQLRecorder) RecordFinal(ctx context.Context, id string, status DeliveryStatus, reason string, evidence DeliveryEvidence, now time.Time) error {
	if s.DB == nil {
		return errors.New("notification delivery db required")
	}
	if !validStatus(status) {
		return errors.New("invalid notification delivery status")
	}
	evidenceJSON, err := json.Marshal(SanitizeDeliveryEvidence(evidence))
	if err != nil {
		return err
	}
	res, err := s.DB.ExecContext(ctx, `UPDATE notification_deliveries SET status=$2, reason=$3, evidence_json=$4, updated_at=$5 WHERE alert_id=$1`, id, status, SanitizeDeliveryReason(reason), string(evidenceJSON), now.UTC())
	if err != nil {
		return err
	}
	if n, err := res.RowsAffected(); err == nil && n == 0 {
		return errors.New("delivery record not found")
	}
	return nil
}

func (s SQLRecorder) Get(ctx context.Context, id string) (DeliveryRecord, bool, error) {
	if s.DB == nil {
		return DeliveryRecord{}, false, errors.New("notification delivery db required")
	}
	var rec DeliveryRecord
	var payload, evidenceJSON string
	err := s.DB.QueryRowContext(ctx, `SELECT alert_json, status, reason, evidence_json, created_at, updated_at FROM notification_deliveries WHERE alert_id=$1`, id).Scan(&payload, &rec.Status, &rec.Reason, &evidenceJSON, &rec.CreatedAt, &rec.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return DeliveryRecord{}, false, nil
	}
	if err != nil {
		return DeliveryRecord{}, false, err
	}
	if err := json.Unmarshal([]byte(payload), &rec.Alert); err != nil {
		return DeliveryRecord{}, false, err
	}
	if err := json.Unmarshal([]byte(evidenceJSON), &rec.Evidence); err != nil {
		return DeliveryRecord{}, false, err
	}
	return rec, true, nil
}

func (s SQLRecorder) List(ctx context.Context) ([]DeliveryRecord, error) {
	if s.DB == nil {
		return nil, errors.New("notification delivery db required")
	}
	rows, err := s.DB.QueryContext(ctx, `SELECT alert_json, status, reason, evidence_json, created_at, updated_at FROM notification_deliveries ORDER BY updated_at DESC, alert_id ASC LIMIT 200`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []DeliveryRecord
	for rows.Next() {
		var rec DeliveryRecord
		var payload, evidenceJSON string
		if err := rows.Scan(&payload, &rec.Status, &rec.Reason, &evidenceJSON, &rec.CreatedAt, &rec.UpdatedAt); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(payload), &rec.Alert); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(evidenceJSON), &rec.Evidence); err != nil {
			return nil, err
		}
		out = append(out, rec)
	}
	return out, rows.Err()
}

func validStatus(status DeliveryStatus) bool {
	switch status {
	case StatusPending, StatusDelivered, StatusFailedRetryable, StatusFailedPermanent:
		return true
	default:
		return false
	}
}
