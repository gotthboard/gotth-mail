package notification

import (
	"context"
	"errors"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityWarning  Severity = "warning"
	SeverityCritical Severity = "critical"
)

type DeliveryStatus string

const (
	StatusPending         DeliveryStatus = "pending"
	StatusDelivered       DeliveryStatus = "delivered"
	StatusFailedRetryable DeliveryStatus = "failed_retryable"
	StatusFailedPermanent DeliveryStatus = "failed_permanent"
)

type ResourceRef struct{ Type, ID string }

type Alert struct {
	ID, Class, Title, Summary, CorrelationID string
	Severity                                 Severity
	Resource                                 ResourceRef
	Details                                  map[string]string
}

type DeliveryResult struct {
	Status DeliveryStatus
	Reason string
}

type DeliveryRecord struct {
	Alert     Alert
	Status    DeliveryStatus
	Reason    string
	CreatedAt time.Time
	UpdatedAt time.Time
}

type Backend interface {
	SendAlert(context.Context, Alert) (DeliveryResult, error)
}

type Recorder interface {
	RecordPending(context.Context, Alert, time.Time) error
	RecordFinal(context.Context, string, DeliveryStatus, string, time.Time) error
	Get(context.Context, string) (DeliveryRecord, bool, error)
	List(context.Context) ([]DeliveryRecord, error)
}

type Service struct {
	Backend  Backend
	Recorder Recorder
	Now      func() time.Time
}

func (s Service) SendAlert(ctx context.Context, alert Alert) (DeliveryRecord, error) {
	if s.Backend == nil {
		return DeliveryRecord{}, errors.New("notification backend required")
	}
	recorder := s.Recorder
	if recorder == nil {
		recorder = NewMemoryRecorder()
	}
	now := s.now()
	clean, err := SanitizeAlert(alert)
	if err != nil {
		return DeliveryRecord{}, err
	}
	if err := recorder.RecordPending(ctx, clean, now); err != nil {
		return DeliveryRecord{}, err
	}
	result, sendErr := s.Backend.SendAlert(ctx, clean)
	status := result.Status
	if status == "" {
		if sendErr != nil {
			status = StatusFailedRetryable
		} else {
			status = StatusDelivered
		}
	}
	if status != StatusDelivered && status != StatusFailedRetryable && status != StatusFailedPermanent {
		status = StatusFailedRetryable
	}
	reason := bound(result.Reason, 256)
	if reason == "" && sendErr != nil {
		reason = bound(sendErr.Error(), 256)
	}
	if err := recorder.RecordFinal(ctx, clean.ID, status, reason, s.now()); err != nil {
		return DeliveryRecord{}, err
	}
	rec, ok, err := recorder.Get(ctx, clean.ID)
	if err != nil {
		return DeliveryRecord{}, err
	}
	if !ok {
		return DeliveryRecord{}, errors.New("delivery record missing after send")
	}
	if sendErr != nil {
		return rec, sendErr
	}
	return rec, nil
}

func (s Service) now() time.Time {
	if s.Now != nil {
		return s.Now().UTC()
	}
	return time.Now().UTC()
}

func SanitizeAlert(a Alert) (Alert, error) {
	a.ID = strings.TrimSpace(a.ID)
	if a.ID == "" {
		return Alert{}, errors.New("alert id required")
	}
	a.Class = boundToken(a.Class, 80)
	if a.Class == "" {
		return Alert{}, errors.New("alert class required")
	}
	switch a.Severity {
	case SeverityInfo, SeverityWarning, SeverityCritical:
	case "":
		a.Severity = SeverityInfo
	default:
		return Alert{}, errors.New("unsupported alert severity")
	}
	a.Title = boundLine(redact(a.Title), 120)
	a.Summary = boundLine(redact(a.Summary), 512)
	if a.Title == "" || a.Summary == "" {
		return Alert{}, errors.New("alert title and summary required")
	}
	a.CorrelationID = boundToken(a.CorrelationID, 128)
	a.Resource.Type = boundToken(a.Resource.Type, 64)
	a.Resource.ID = boundLine(redact(a.Resource.ID), 160)
	if len(a.Details) > 20 {
		return Alert{}, errors.New("alert details too large")
	}
	clean := map[string]string{}
	for k, v := range a.Details {
		key := boundToken(k, 64)
		if key == "" {
			return Alert{}, errors.New("alert detail key required")
		}
		if secretKey.MatchString(key) {
			clean[key] = "[REDACTED]"
			continue
		}
		if strings.Count(v, "\n") > 3 || len(v) > 2048 {
			return Alert{}, errors.New("alert detail value too large")
		}
		clean[key] = bound(redact(v), 1024)
	}
	a.Details = clean
	return a, nil
}

var secretValue = regexp.MustCompile(`(?i)(password\s*[=:]\s*\S+|token\s*[=:]\s*\S+|secret\s*[=:]\s*\S+|-----BEGIN [A-Z ]*PRIVATE KEY-----)`) // broad by design
var secretKey = regexp.MustCompile(`(?i)(password|token|secret|private[_-]?key)`)

func redact(v string) string { return secretValue.ReplaceAllString(v, "[REDACTED]") }
func bound(v string, n int) string {
	v = strings.TrimSpace(v)
	if len(v) <= n {
		return v
	}
	if n <= 1 {
		return v[:n]
	}
	return v[:n-1] + "."
}
func boundLine(v string, n int) string {
	v = strings.Join(strings.Fields(v), " ")
	return bound(v, n)
}
func boundToken(v string, n int) string {
	v = strings.ToLower(strings.TrimSpace(v))
	if strings.ContainsAny(v, " \r\n\t") {
		v = strings.ReplaceAll(v, " ", "-")
	}
	return bound(v, n)
}

type MemoryRecorder struct {
	mu      sync.Mutex
	records map[string]DeliveryRecord
}

func NewMemoryRecorder() *MemoryRecorder {
	return &MemoryRecorder{records: map[string]DeliveryRecord{}}
}

func (m *MemoryRecorder) RecordPending(ctx context.Context, a Alert, now time.Time) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.records == nil {
		m.records = map[string]DeliveryRecord{}
	}
	m.records[a.ID] = DeliveryRecord{Alert: a, Status: StatusPending, CreatedAt: now, UpdatedAt: now}
	return nil
}
func (m *MemoryRecorder) RecordFinal(ctx context.Context, id string, status DeliveryStatus, reason string, now time.Time) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.records[id]
	if !ok {
		return errors.New("delivery record not found")
	}
	r.Status, r.Reason, r.UpdatedAt = status, reason, now
	m.records[id] = r
	return nil
}
func (m *MemoryRecorder) Get(ctx context.Context, id string) (DeliveryRecord, bool, error) {
	if err := ctx.Err(); err != nil {
		return DeliveryRecord{}, false, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.records[id]
	return r, ok, nil
}
func (m *MemoryRecorder) List(ctx context.Context) ([]DeliveryRecord, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]DeliveryRecord, 0, len(m.records))
	for _, r := range m.records {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Alert.ID < out[j].Alert.ID })
	return out, nil
}
