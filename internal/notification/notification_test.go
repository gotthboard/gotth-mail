package notification

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

type fakeBackend struct {
	got    Alert
	res    DeliveryResult
	err    error
	called bool
}

func (f *fakeBackend) SendAlert(ctx context.Context, a Alert) (DeliveryResult, error) {
	f.called = true
	f.got = a
	return f.res, f.err
}

func baseAlert() Alert {
	return Alert{ID: "alert-1", Class: "auth.failure", Severity: SeverityWarning, Title: "Auth failure", Summary: "login failed", CorrelationID: "corr-1", Resource: ResourceRef{Type: "session", ID: "sess-1"}, Details: map[string]string{"ip": "127.0.0.1"}}
}

func TestSendAlertRecordsDeliveredStatus(t *testing.T) {
	rec := NewMemoryRecorder()
	backend := &fakeBackend{res: DeliveryResult{Status: StatusDelivered}}
	svc := Service{Backend: backend, Recorder: rec, Now: func() time.Time { return time.Unix(1, 0) }}
	got, err := svc.SendAlert(context.Background(), baseAlert())
	if err != nil {
		t.Fatal(err)
	}
	if !backend.called || got.Status != StatusDelivered || got.Alert.ID != "alert-1" {
		t.Fatalf("called=%v got=%#v", backend.called, got)
	}
	listed, err := rec.List(context.Background())
	if err != nil || len(listed) != 1 || listed[0].Status != StatusDelivered {
		t.Fatalf("listed=%#v err=%v", listed, err)
	}
}

func TestSendAlertRecordsRetryableFailureVisibleInStatus(t *testing.T) {
	rec := NewMemoryRecorder()
	backend := &fakeBackend{res: DeliveryResult{Status: StatusFailedRetryable, Reason: "telegram unavailable"}, err: errors.New("send failed")}
	svc := Service{Backend: backend, Recorder: rec}
	got, err := svc.SendAlert(context.Background(), baseAlert())
	if err == nil || got.Status != StatusFailedRetryable || got.Reason != "telegram unavailable" {
		t.Fatalf("got=%#v err=%v", got, err)
	}
	stored, ok, err := rec.Get(context.Background(), "alert-1")
	if err != nil || !ok || stored.Status != StatusFailedRetryable || stored.Reason == "" {
		t.Fatalf("stored=%#v ok=%v err=%v", stored, ok, err)
	}
}

func TestSendAlertRedactsSecretsBeforeBackend(t *testing.T) {
	backend := &fakeBackend{res: DeliveryResult{Status: StatusDelivered}}
	a := baseAlert()
	a.Summary = "password=hunter2 token=abcdef"
	a.Details = map[string]string{"token": "abcdef", "log": "secret=value"}
	if _, err := (Service{Backend: backend, Recorder: NewMemoryRecorder()}).SendAlert(context.Background(), a); err != nil {
		t.Fatal(err)
	}
	joined := backend.got.Summary + " " + backend.got.Details["token"] + " " + backend.got.Details["log"]
	if strings.Contains(joined, "hunter2") || strings.Contains(joined, "abcdef") || strings.Contains(joined, "secret=value") || !strings.Contains(joined, "[REDACTED]") {
		t.Fatalf("secrets leaked to backend: %#v", backend.got)
	}
}

func TestSendAlertBoundsSummaryAndDetails(t *testing.T) {
	backend := &fakeBackend{res: DeliveryResult{Status: StatusDelivered}}
	a := baseAlert()
	a.Title = strings.Repeat("t", 200)
	a.Summary = strings.Repeat("s", 900)
	a.Details = map[string]string{"blob": strings.Repeat("x", 1500)}
	got, err := (Service{Backend: backend, Recorder: NewMemoryRecorder()}).SendAlert(context.Background(), a)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Alert.Title) > 120 || len(got.Alert.Summary) > 512 || len(got.Alert.Details["blob"]) > 1024 {
		t.Fatalf("not bounded: %#v", got.Alert)
	}
	a.Details = map[string]string{"raw_log": "a\nb\nc\nd\ne"}
	if _, err := (Service{Backend: backend, Recorder: NewMemoryRecorder()}).SendAlert(context.Background(), a); err == nil {
		t.Fatal("raw multiline log was accepted")
	}
}

func TestBackendReceivesOnlySanitizedAlertContract(t *testing.T) {
	backend := &fakeBackend{res: DeliveryResult{Status: StatusDelivered}}
	if _, err := (Service{Backend: backend, Recorder: NewMemoryRecorder()}).SendAlert(context.Background(), baseAlert()); err != nil {
		t.Fatal(err)
	}
	if backend.got.ID == "" || backend.got.Resource.ID != "sess-1" {
		t.Fatalf("backend did not receive alert contract: %#v", backend.got)
	}
	// The backend interface is intentionally only SendAlert(ctx, Alert): no DB,
	// control-plane store, approval callback, or mutation handle is passed.
}
