package notification

import (
	"context"
	"strings"
	"testing"
	"time"

	"forgejo/linus/gophermailforge/internal/store"
	"forgejo/linus/gophermailforge/internal/testpg"
)

func TestSQLRecorderPersistsDeliveryStatusAcrossReload(t *testing.T) {
	db := testpg.DB(t, store.MigrateSQL)
	rec := SQLRecorder{DB: db}
	now := time.Unix(1, 0).UTC()
	a := baseAlert()
	a.Summary = "token=secret-token delivery failed"
	if err := rec.RecordPending(context.Background(), a, now); err != nil {
		t.Fatal(err)
	}
	if err := rec.RecordFinal(context.Background(), a.ID, StatusFailedRetryable, strings.Repeat("x", 400), now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	got, ok, err := (SQLRecorder{DB: db}).Get(context.Background(), a.ID)
	if err != nil || !ok {
		t.Fatalf("ok=%v err=%v", ok, err)
	}
	if got.Status != StatusFailedRetryable || len(got.Reason) > 256 || got.Alert.Summary == a.Summary || strings.Contains(got.Alert.Summary, "secret-token") {
		t.Fatalf("bad stored record: %#v", got)
	}
	listed, err := rec.List(context.Background())
	if err != nil || len(listed) != 1 || listed[0].Alert.ID != a.ID {
		t.Fatalf("listed=%#v err=%v", listed, err)
	}
}

func TestSQLRecorderRejectsUnknownFinalAndInvalidStatus(t *testing.T) {
	db := testpg.DB(t, store.MigrateSQL)
	rec := SQLRecorder{DB: db}
	if err := rec.RecordFinal(context.Background(), "missing", StatusDelivered, "", time.Unix(1, 0)); err == nil {
		t.Fatal("unknown delivery accepted")
	}
	if err := rec.RecordPending(context.Background(), baseAlert(), time.Unix(1, 0)); err != nil {
		t.Fatal(err)
	}
	if err := rec.RecordFinal(context.Background(), "alert-1", DeliveryStatus("sent-ish"), "", time.Unix(2, 0)); err == nil {
		t.Fatal("invalid status accepted")
	}
}
