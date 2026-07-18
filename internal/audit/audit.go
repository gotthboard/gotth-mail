package audit

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"strings"
	"sync"
	"time"
)

type ActorRef struct{ Type, ID string }
type ResourceRef struct{ Type, ID string }
type RequestSource struct{ IP, UserAgent string }

type Event struct {
	ID             string
	Time           time.Time
	Actor          ActorRef
	Source         *RequestSource
	Action         string
	Resource       ResourceRef
	BeforeRedacted any
	AfterRedacted  any
	CorrelationID  string
	Result         string
	ErrorCode      string
}

type Writer interface {
	Write(ctx context.Context, e Event) error
}

type MemoryWriter struct {
	mu     sync.Mutex
	Events []Event
}

func Normalize(e Event) Event {
	if e.ID == "" {
		e.ID = newUUID()
	}
	if e.Time.IsZero() {
		e.Time = time.Now().UTC()
	}
	e.BeforeRedacted = Redact(e.BeforeRedacted)
	e.AfterRedacted = Redact(e.AfterRedacted)
	return e
}

func (w *MemoryWriter) Write(ctx context.Context, e Event) error {
	e = Normalize(e)
	w.mu.Lock()
	defer w.mu.Unlock()
	w.Events = append(w.Events, e)
	return nil
}

type SQLWriter struct{ DB *sql.DB }

func (w SQLWriter) Write(ctx context.Context, e Event) error {
	e = Normalize(e)
	before, err := json.Marshal(e.BeforeRedacted)
	if err != nil {
		return err
	}
	after, err := json.Marshal(e.AfterRedacted)
	if err != nil {
		return err
	}
	var sourceIP, sourceUA sql.NullString
	if e.Source != nil {
		sourceIP = sql.NullString{String: e.Source.IP, Valid: e.Source.IP != ""}
		sourceUA = sql.NullString{String: e.Source.UserAgent, Valid: e.Source.UserAgent != ""}
	}
	_, err = w.DB.ExecContext(ctx, `INSERT INTO audit_events(id, timestamp, actor_type, actor_id, source_ip, source_user_agent, action, resource_type, resource_id, before_redacted_json, after_redacted_json, correlation_id, result, error_code) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`, e.ID, e.Time, e.Actor.Type, e.Actor.ID, sourceIP, sourceUA, e.Action, e.Resource.Type, e.Resource.ID, string(before), string(after), e.CorrelationID, e.Result, nullString(e.ErrorCode))
	return err
}

func nullString(s string) sql.NullString { return sql.NullString{String: s, Valid: s != ""} }

func newUUID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "00000000-0000-4000-8000-000000000000"
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	s := hex.EncodeToString(b[:])
	return s[0:8] + "-" + s[8:12] + "-" + s[12:16] + "-" + s[16:20] + "-" + s[20:32]
}

var secretKeys = []string{"password", "token", "secret", "private_key", "client_secret", "app_password", "verifier", "key"}

func Redact(v any) any {
	b, _ := json.Marshal(v)
	var x any
	if json.Unmarshal(b, &x) != nil {
		return v
	}
	return redactValue(x)
}
func redactValue(v any) any {
	switch t := v.(type) {
	case map[string]any:
		out := map[string]any{}
		for k, val := range t {
			if isSecret(k) {
				out[k] = "[REDACTED]"
			} else {
				out[k] = redactValue(val)
			}
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, val := range t {
			out[i] = redactValue(val)
		}
		return out
	default:
		return v
	}
}
func isSecret(k string) bool {
	k = strings.ToLower(k)
	for _, s := range secretKeys {
		if strings.Contains(k, s) {
			return true
		}
	}
	return false
}
func ContainsSecretJSON(v any, needles ...string) bool {
	return containsSecretValue(v, needles...)
}

func containsSecretValue(v any, needles ...string) bool {
	switch t := v.(type) {
	case map[string]any:
		for _, val := range t {
			if containsSecretValue(val, needles...) {
				return true
			}
		}
		return false
	case []any:
		for _, val := range t {
			if containsSecretValue(val, needles...) {
				return true
			}
		}
		return false
	case string:
		s := strings.ToLower(t)
		for _, n := range needles {
			if strings.Contains(s, strings.ToLower(n)) {
				return true
			}
		}
		return false
	default:
		return false
	}
}
