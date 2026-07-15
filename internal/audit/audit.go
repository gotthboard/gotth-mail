package audit

import (
	"context"
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

func (w *MemoryWriter) Write(ctx context.Context, e Event) error {
	if e.ID == "" {
		e.ID = "audit-" + time.Now().UTC().Format("20060102150405.000000000")
	}
	if e.Time.IsZero() {
		e.Time = time.Now().UTC()
	}
	e.BeforeRedacted = Redact(e.BeforeRedacted)
	e.AfterRedacted = Redact(e.AfterRedacted)
	w.mu.Lock()
	defer w.mu.Unlock()
	w.Events = append(w.Events, e)
	return nil
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
