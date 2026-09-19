package notifyruntime

import (
	"context"
	"errors"
	"testing"
	"time"

	"forgejo/gotthboard/gotth-mail/internal/notification"
	"forgejo/gotthboard/gotth-mail/internal/ops"
	"forgejo/gotthboard/gotth-mail/internal/store"
	"forgejo/gotthboard/gotth-mail/internal/testpg"
)

type monitorBackend struct {
	calls int
	fail  bool
}

func (b *monitorBackend) SendAlert(context.Context, notification.Alert) (notification.DeliveryResult, error) {
	b.calls++
	if b.fail {
		return notification.DeliveryResult{Status: notification.StatusFailedRetryable, Reason: "fixture_unavailable"}, errors.New("fixture unavailable")
	}
	return notification.DeliveryResult{Status: notification.StatusDelivered, Reason: "fixture_delivered"}, nil
}

func TestOperationalMonitorSendsOnlyOnDurableFailureTransitions(t *testing.T) {
	db := testpg.DB(t, store.MigrateSQL)
	backend := &monitorBackend{}
	status := ops.Fail
	now := time.Unix(100, 0).UTC()
	monitor := OperationalMonitor{
		Service: &notification.Service{Backend: backend, Recorder: notification.SQLRecorder{DB: db}, Now: func() time.Time { return now }},
		States:  SQLNotificationEventStates{DB: db},
		Doctor: func(context.Context) (ops.DoctorReport, error) {
			return ops.DoctorReport{Status: status, Checks: []ops.Check{{Category: "plugin", Name: "telegram", Status: status}}}, nil
		},
		Now: func() time.Time { return now },
	}
	if err := monitor.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := monitor.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if backend.calls != 1 {
		t.Fatalf("unchanged failure sent %d times", backend.calls)
	}
	status = ops.OK
	now = now.Add(time.Minute)
	if err := monitor.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	status = ops.Fail
	now = now.Add(time.Minute)
	if err := monitor.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if backend.calls != 2 {
		t.Fatalf("recurrent transition sends=%d want=2", backend.calls)
	}
	var deliveries int
	if err := db.QueryRow(`SELECT count(*) FROM notification_deliveries WHERE status='delivered'`).Scan(&deliveries); err != nil || deliveries != 2 {
		t.Fatalf("deliveries=%d err=%v", deliveries, err)
	}
}

func TestOperationalMonitorRetriesPendingDeliveryWithoutNewEvent(t *testing.T) {
	db := testpg.DB(t, store.MigrateSQL)
	backend := &monitorBackend{fail: true}
	monitor := OperationalMonitor{
		Service: &notification.Service{Backend: backend, Recorder: notification.SQLRecorder{DB: db}},
		States:  SQLNotificationEventStates{DB: db},
		Doctor: func(context.Context) (ops.DoctorReport, error) {
			return ops.DoctorReport{Status: ops.Fail, Checks: []ops.Check{{Category: "TLS", Name: "certificate", Status: ops.Fail}}}, nil
		},
	}
	if err := monitor.RunOnce(context.Background()); err == nil {
		t.Fatal("retryable delivery failure was hidden")
	}
	backend.fail = false
	if err := monitor.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if backend.calls != 2 {
		t.Fatalf("retry calls=%d", backend.calls)
	}
	var pending int
	if err := db.QueryRow(`SELECT count(*) FROM notification_event_states WHERE pending_alert_id IS NOT NULL`).Scan(&pending); err != nil || pending != 0 {
		t.Fatalf("pending states=%d err=%v", pending, err)
	}
}
