package notification

import (
	"context"
	"errors"
	"net/mail"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"
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
	Status   DeliveryStatus
	Reason   string
	Evidence DeliveryEvidence
}

type DeliveryEvidence struct {
	Transport           string    `json:"transport,omitempty"`
	MessageID           string    `json:"message_id,omitempty"`
	GeneratedAt         time.Time `json:"generated_at,omitzero"`
	From                string    `json:"from,omitempty"`
	Sender              string    `json:"sender,omitempty"`
	SigningFingerprint  string    `json:"signing_fingerprint,omitempty"`
	SenderIdentityID    string    `json:"sender_identity_id,omitempty"`
	SenderIdentityClass string    `json:"sender_identity_class,omitempty"`
	PolicyVersion       string    `json:"policy_version,omitempty"`
	IdentityStateRef    string    `json:"identity_state_ref,omitempty"`
	VerificationResult  string    `json:"verification_result,omitempty"`
	Workflow            string    `json:"workflow,omitempty"`
}

type DeliveryRecord struct {
	Alert     Alert
	Status    DeliveryStatus
	Reason    string
	Evidence  DeliveryEvidence `json:",omitzero"`
	CreatedAt time.Time
	UpdatedAt time.Time
}

type Backend interface {
	SendAlert(context.Context, Alert) (DeliveryResult, error)
}

type Recorder interface {
	RecordPending(context.Context, Alert, time.Time) error
	RecordFinal(context.Context, string, DeliveryStatus, string, DeliveryEvidence, time.Time) error
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
	reason := SanitizeDeliveryReason(result.Reason)
	if reason == "" && sendErr != nil {
		reason = SanitizeDeliveryReason(sendErr.Error())
	}
	evidence := SanitizeDeliveryEvidence(result.Evidence)
	if err := recorder.RecordFinal(ctx, clean.ID, status, reason, evidence, s.now()); err != nil {
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
	for _, value := range []string{a.ID, a.Class, a.Title, a.Summary, a.CorrelationID, a.Resource.Type, a.Resource.ID} {
		if !utf8.ValidString(value) {
			return Alert{}, errors.New("alert text must be valid UTF-8")
		}
	}
	for key, value := range a.Details {
		if !utf8.ValidString(key) || !utf8.ValidString(value) {
			return Alert{}, errors.New("alert detail text must be valid UTF-8")
		}
	}
	for _, value := range []string{a.ID, a.Class, a.CorrelationID, a.Resource.Type} {
		if hasSecretIdentifier(value) {
			return Alert{}, errors.New("alert identifiers must not contain secret markers")
		}
	}
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
	redactedKeys := map[string]bool{}
	for k, v := range a.Details {
		normalizedKey := normalizeToken(k)
		key := bound(normalizedKey, 64)
		if key == "" {
			return Alert{}, errors.New("alert detail key required")
		}
		if hasSecretIdentifier(normalizedKey) {
			clean[key] = "[REDACTED]"
			redactedKeys[key] = true
			continue
		}
		if redactedKeys[key] {
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

var privateKeyMarker = regexp.MustCompile(`(?i)-----BEGIN [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----`)
var secretAssignment = regexp.MustCompile(`(?i)(?:^|[^A-Z0-9_])"?(?:password|token|secret|authorization|apikey|api[ _-]*key|private[ _-]*key|(?:[A-Z0-9]+(?:[_.-][A-Z0-9]+)*)[_.-](?:password|token|secret))"?\s*[=:]`)
var bearerValue = regexp.MustCompile(`(?i)\bbearer\s+\S+`)
var secretKey = regexp.MustCompile(`(?i)^"?(?:password|token|secret|authorization|apikey|api[_-]?key|private[_-]?key|(?:[A-Z0-9]+(?:[_.-][A-Z0-9]+)*)[_.-](?:password|token|secret))"?$`)
var deliveryReason = regexp.MustCompile(`^[A-Za-z0-9._:@;=<>-]+$`)
var evidenceTransport = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9._-]*$`)
var evidenceMessageID = regexp.MustCompile(`^<[A-Za-z0-9][A-Za-z0-9._+/-]*@[A-Za-z0-9][A-Za-z0-9.-]*>$`)
var evidenceFingerprint = regexp.MustCompile(`^(?:[A-Fa-f0-9]{40}|[A-Fa-f0-9]{64})$`)
var evidenceIdentityID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:@+/-]*$`)
var evidenceClass = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9._-]*$`)
var evidencePolicyVersion = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)
var evidenceStateRef = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9._:+/-]*$`)
var evidenceVerification = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9._-]*$`)
var evidenceWorkflow = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9._-]*$`)

func redact(v string) string {
	if hasSecretMarker(v) {
		return "[REDACTED]"
	}
	return v
}

func hasSecretMarker(v string) bool {
	scan := normalizeSecretWhitespace(v)
	return privateKeyMarker.MatchString(scan) || secretAssignment.MatchString(scan) || bearerValue.MatchString(scan)
}

func hasSecretIdentifier(v string) bool {
	return hasSecretMarker(v) || secretKey.MatchString(normalizeToken(v))
}

func normalizeSecretWhitespace(v string) string {
	for _, r := range v {
		if r != ' ' && unicode.IsSpace(r) {
			return strings.Map(func(r rune) rune {
				if unicode.IsSpace(r) {
					return ' '
				}
				return r
			}, v)
		}
	}
	return v
}

// SanitizeDeliveryReason enforces the narrow machine-readable reason grammar
// shared by persistence and the plugin boundary. Human prose and dependency
// errors do not belong in this field.
func SanitizeDeliveryReason(v string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return ""
	}
	redacted := redact(v)
	if redacted != v || len(v) > 256 || !utf8.ValidString(v) || !deliveryReason.MatchString(v) {
		return "delivery_reason_redacted"
	}
	return v
}

func SanitizeDeliveryEvidence(in DeliveryEvidence) DeliveryEvidence {
	out := DeliveryEvidence{
		Transport:           safeEvidencePattern(in.Transport, 32, evidenceTransport),
		MessageID:           safeEvidencePattern(in.MessageID, 255, evidenceMessageID),
		From:                safeEvidenceAddress(in.From),
		Sender:              safeEvidenceAddress(in.Sender),
		SigningFingerprint:  safeEvidencePattern(in.SigningFingerprint, 64, evidenceFingerprint),
		SenderIdentityID:    safeEvidencePattern(in.SenderIdentityID, 320, evidenceIdentityID),
		SenderIdentityClass: safeEvidencePattern(in.SenderIdentityClass, 32, evidenceClass),
		PolicyVersion:       safeEvidencePattern(in.PolicyVersion, 64, evidencePolicyVersion),
		IdentityStateRef:    safeEvidencePattern(in.IdentityStateRef, 160, evidenceStateRef),
		VerificationResult:  safeEvidencePattern(in.VerificationResult, 64, evidenceVerification),
		Workflow:            safeEvidencePattern(in.Workflow, 64, evidenceWorkflow),
	}
	if !in.GeneratedAt.IsZero() {
		out.GeneratedAt = in.GeneratedAt.UTC()
	}
	return out
}

func safeEvidencePattern(v string, n int, pattern *regexp.Regexp) string {
	v = strings.TrimSpace(v)
	if v == "" || len(v) > n || !utf8.ValidString(v) || hasSecretIdentifier(v) || !pattern.MatchString(v) {
		return ""
	}
	return v
}

func safeEvidenceAddress(v string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return ""
	}
	if len(v) > 320 || !utf8.ValidString(v) || hasSecretIdentifier(v) || strings.ContainsAny(v, "\r\n") {
		return ""
	}
	address, err := mail.ParseAddress(v)
	if err != nil || address.Address != v {
		return ""
	}
	return v
}

func bound(v string, n int) string {
	v = strings.TrimSpace(v)
	if len(v) <= n {
		return v
	}
	if n <= 0 {
		return ""
	}
	if n == 1 {
		return "."
	}
	cut := n - 1
	for cut > 0 && !utf8.RuneStart(v[cut]) {
		cut--
	}
	return v[:cut] + "."
}
func boundLine(v string, n int) string {
	v = strings.Join(strings.Fields(v), " ")
	return bound(v, n)
}
func boundToken(v string, n int) string {
	return bound(normalizeToken(v), n)
}

func normalizeToken(v string) string {
	v = strings.ToLower(strings.TrimSpace(v))
	return strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) {
			return '-'
		}
		return r
	}, v)
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
func (m *MemoryRecorder) RecordFinal(ctx context.Context, id string, status DeliveryStatus, reason string, evidence DeliveryEvidence, now time.Time) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.records[id]
	if !ok {
		return errors.New("delivery record not found")
	}
	r.Status, r.Reason, r.Evidence, r.UpdatedAt = status, reason, SanitizeDeliveryEvidence(evidence), now
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
